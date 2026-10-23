using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetWarden
{
    internal sealed class AppInfo
    {
        public string Key;          // lowercase full path, or "system"/"unknown"/"name:xxx"
        public string Path;         // may be null for special entries
        public string Name;         // friendly display name
        public string FileName;
        public bool Special;        // System / Unknown

        public long Down, Up;               // total bytes (written by engine threads)
        public long BlockedPackets, DroppedPackets;
        public volatile Shaping Shape;      // null = no rule
        public int Connections;             // from last table snapshot
        public readonly HashSet<uint> Pids = new HashSet<uint>();

        // UI-thread-only fields
        public long PrevDown, PrevUp;
        public double RateDown, RateUp;
        public DateTime LastActive = DateTime.MinValue;
    }

    internal sealed class Shaping
    {
        public bool Block;
        public Bucket Down, Up;
    }

    internal sealed class QPacket
    {
        public byte[] Data;
        public byte[] Addr;
        public IntPtr Handle;
        public AppInfo App;
        public bool Outbound;
    }

    /// <summary>Token bucket with a bounded queue. Packets that exceed the rate are delayed (not dropped)
    /// until the queue is full, which gives smooth TCP-friendly shaping.</summary>
    internal sealed class Bucket
    {
        readonly object _lock = new object();
        readonly Queue<QPacket> _q = new Queue<QPacket>();
        readonly Action<QPacket> _sink;
        double _tokens, _rate, _burst;
        long _qBytes, _maxQ;
        public Bucket Next;

        public Bucket(double bytesPerSec, Action<QPacket> sink)
        {
            _sink = sink;
            _rate = bytesPerSec;
            _burst = Math.Max(bytesPerSec * 0.05, 4500);
            _maxQ = (long)Math.Max(bytesPerSec * 0.5, 32 * 1024);
            _tokens = _burst;
        }

        public void Push(QPacket p)
        {
            lock (_lock)
            {
                if (_q.Count == 0 && _tokens >= 0)
                {
                    _tokens -= p.Data.Length;
                    Forward(p);
                    return;
                }
                if (_qBytes + p.Data.Length > _maxQ)
                {
                    Interlocked.Increment(ref p.App.DroppedPackets);
                    return; // tail drop -> TCP backs off
                }
                _q.Enqueue(p);
                _qBytes += p.Data.Length;
            }
        }

        public void Tick(double dt)
        {
            lock (_lock)
            {
                _tokens += _rate * dt;
                if (_tokens > _burst) _tokens = _burst;
                while (_q.Count > 0 && _tokens >= 0)
                {
                    var p = _q.Dequeue();
                    _qBytes -= p.Data.Length;
                    _tokens -= p.Data.Length;
                    Forward(p);
                }
            }
        }

        public void FlushAll()
        {
            lock (_lock)
            {
                while (_q.Count > 0) { var p = _q.Dequeue(); Forward(p); }
                _qBytes = 0;
            }
        }

        void Forward(QPacket p)
        {
            if (Next != null) Next.Push(p); else _sink(p);
        }
    }

    internal sealed unsafe class TrafficEngine : IDisposable
    {
        const string NetFilter = "!loopback and (tcp or udp)";

        readonly uint[] _tcpPid = new uint[65536];
        readonly uint[] _udpPid = new uint[65536];
        readonly ConcurrentDictionary<uint, AppInfo> _pidApp = new ConcurrentDictionary<uint, AppInfo>();
        readonly ConcurrentDictionary<string, AppInfo> _apps = new ConcurrentDictionary<string, AppInfo>();
        public readonly AppInfo UnknownApp, SystemApp, HotspotApp;

        IntPtr _sniff = IntPtr.Zero, _flow = IntPtr.Zero;
        volatile IntPtr _divert = IntPtr.Zero;
        Thread _divertThread;

        // ---- Mobile Hotspot / Internet Connection Sharing ----
        // Traffic Windows relays for devices on the hotspot has no owning app. Downloads show up at the
        // network layer on a NAT port nobody owns; uploads only at the forward layer. Each direction is taken
        // from whichever layer actually sees it, so nothing is counted (or shaped) twice.
        IntPtr _fwdSniff = IntPtr.Zero;
        volatile IntPtr _fwdDivert = IntPtr.Zero;
        volatile bool _fwdDivertActive;
        Thread _fwdDivertThread;
        volatile uint _hsNet = 0xC0A88900, _hsMask = 0xFFFFFF00;   // 192.168.137.0/24 (Windows default)
        volatile bool _hsAdapter;
        long _seenNdown = -100000, _seenNup = -100000, _seenFdown = -100000, _seenFup = -100000;
        static readonly Stopwatch Clock = Stopwatch.StartNew();
        const int SRC_NET = 0, SRC_FWD = 1;
        volatile bool _running, _divertActive;
        int _refreshRequested;

        public long TotalDown, TotalUp;
        public volatile List<ConnInfo> Connections = new List<ConnInfo>();
        public volatile bool WantConnections = true;
        public volatile string LastError;

        // ---- rules / shaping state (guarded by _rulesLock) ----
        readonly object _rulesLock = new object();
        Dictionary<string, Rule> _rules = new Dictionary<string, Rule>();
        volatile Bucket _gDown, _gUp;
        volatile Bucket[] _active = new Bucket[0];
        readonly List<KeyValuePair<Bucket, DateTime>> _retired = new List<KeyValuePair<Bucket, DateTime>>();

        public bool ShapingActive { get { return _divertActive; } }
        public IEnumerable<AppInfo> Apps { get { return _apps.Values; } }

        public TrafficEngine()
        {
            UnknownApp = new AppInfo { Key = "unknown", Name = "Unknown / pending", FileName = "", Special = true };
            SystemApp = new AppInfo { Key = "system", Name = "System (kernel)", FileName = "System", Special = true };
            HotspotApp = new AppInfo { Key = "hotspot", Name = "Mobile Hotspot", Special = true,
                FileName = "Phones / PCs connected to this PC's Mobile Hotspot or shared connection" };
            _apps[UnknownApp.Key] = UnknownApp;
            _apps[HotspotApp.Key] = HotspotApp;
            _apps[SystemApp.Key] = SystemApp;
        }

        // ================= lifecycle =================

        public bool Start(out string error)
        {
            error = null;
            _flow = WD.WinDivertOpen("true", WD.LAYER_FLOW, 0, WD.FLAG_SNIFF | WD.FLAG_RECV_ONLY);
            if (!WD.IsValid(_flow)) { error = WD.Explain(Marshal.GetLastWin32Error()); return false; }

            _sniff = WD.WinDivertOpen(NetFilter, WD.LAYER_NETWORK, 0, WD.FLAG_SNIFF | WD.FLAG_RECV_ONLY);
            if (!WD.IsValid(_sniff))
            {
                error = WD.Explain(Marshal.GetLastWin32Error());
                WD.WinDivertClose(_flow); _flow = IntPtr.Zero;
                return false;
            }
            WD.WinDivertSetParam(_sniff, WD.PARAM_QUEUE_LENGTH, 8192);
            WD.WinDivertSetParam(_sniff, WD.PARAM_QUEUE_SIZE, 8 * 1024 * 1024);

            _fwdSniff = WD.WinDivertOpen("ip", WD.LAYER_NETWORK_FORWARD, 0, WD.FLAG_SNIFF | WD.FLAG_RECV_ONLY);
            if (WD.IsValid(_fwdSniff)) WD.WinDivertSetParam(_fwdSniff, WD.PARAM_QUEUE_LENGTH, 8192);

            _running = true;
            try { NetTables.Snapshot(_tcpPid, _udpPid, false); } catch { }
            try { DetectHotspot(); } catch { }
            if (WD.IsValid(_fwdSniff)) StartThread(ForwardSniffLoop, "nw-fwd", ThreadPriority.AboveNormal);
            StartThread(FlowLoop, "nw-flow", ThreadPriority.AboveNormal);
            StartThread(SniffLoop, "nw-sniff", ThreadPriority.AboveNormal);
            StartThread(SchedulerLoop, "nw-sched", ThreadPriority.Highest);
            StartThread(TableLoop, "nw-tables", ThreadPriority.BelowNormal);
            return true;
        }

        static Thread StartThread(ThreadStart fn, string name, ThreadPriority prio)
        {
            var t = new Thread(fn) { IsBackground = true, Name = name, Priority = prio };
            t.Start();
            return t;
        }

        public void Dispose()
        {
            if (!_running) return;
            Thread dt;
            lock (_rulesLock) { dt = StopDivert(); }
            if (dt != null) dt.Join(2000);
            _running = false;
            if (WD.IsValid(_sniff)) WD.WinDivertShutdown(_sniff, WD.SHUTDOWN_BOTH);
            if (WD.IsValid(_flow)) WD.WinDivertShutdown(_flow, WD.SHUTDOWN_BOTH);
            if (WD.IsValid(_fwdSniff)) WD.WinDivertShutdown(_fwdSniff, WD.SHUTDOWN_BOTH);
            Thread.Sleep(80);
            if (WD.IsValid(_fwdSniff)) WD.WinDivertClose(_fwdSniff);
            _fwdSniff = IntPtr.Zero;
            if (WD.IsValid(_sniff)) WD.WinDivertClose(_sniff);
            if (WD.IsValid(_flow)) WD.WinDivertClose(_flow);
            _sniff = _flow = IntPtr.Zero;
        }

        // ================= process attribution =================

        AppInfo Resolve(int proto, int port)
        {
            uint pid = 0;
            if (port > 0)
            {
                if (proto == 6) pid = _tcpPid[port];
                else if (proto == 17) pid = _udpPid[port];
            }
            if (pid == 0)
            {
                if (port > 0) Interlocked.Exchange(ref _refreshRequested, 1);
                return UnknownApp;
            }
            return AppForPid(pid);
        }

        public AppInfo AppForPid(uint pid)
        {
            AppInfo a;
            if (_pidApp.TryGetValue(pid, out a)) return a;
            a = CreateForPid(pid);
            _pidApp[pid] = a;
            return a;
        }

        AppInfo CreateForPid(uint pid)
        {
            if (pid == 4) return SystemApp;
            string path = ProcInfo.GetPath(pid);
            string key, name, file;
            if (path != null)
            {
                key = path.ToLowerInvariant();
                file = System.IO.Path.GetFileName(path);
                name = null;
            }
            else
            {
                file = ProcInfo.GetName(pid) ?? ("PID " + pid);
                key = "name:" + file.ToLowerInvariant();
                name = file;
            }

            AppInfo app;
            lock (_rulesLock)
            {
                if (!_apps.TryGetValue(key, out app))
                {
                    app = new AppInfo
                    {
                        Key = key, Path = path, FileName = file,
                        Name = name ?? ProcInfo.FriendlyName(path)
                    };
                    app.Shape = BuildShape(key, _rules, _gDown, _gUp, null);
                    if (app.Shape != null)
                    {
                        // register the new buckets with the scheduler (before the global ones)
                        var list = new List<Bucket>();
                        if (app.Shape.Down != null) list.Add(app.Shape.Down);
                        if (app.Shape.Up != null) list.Add(app.Shape.Up);
                        list.AddRange(_active);
                        _active = list.ToArray();
                    }
                    _apps[key] = app;
                }
            }
            lock (app.Pids) app.Pids.Add(pid);
            return app;
        }

        // ================= counting =================

        void Count(AppInfo app, bool outbound, int len)
        {
            if (outbound) { Interlocked.Add(ref app.Up, len); Interlocked.Add(ref TotalUp, len); }
            else { Interlocked.Add(ref app.Down, len); Interlocked.Add(ref TotalDown, len); }
        }

        /// <summary>Parses one packet at p. Returns its length (0 if unparseable).</summary>
        static int Parse(byte* p, uint avail, bool outbound, out int proto, out int lport)
        {
            uint s4, d4;
            return Parse(p, avail, outbound, out proto, out lport, out s4, out d4);
        }

        static int Parse(byte* p, uint avail, bool outbound, out int proto, out int lport, out uint src4, out uint dst4)
        {
            byte* ip4 = null, ip6 = null, tcp = null, udp = null, next = null;
            byte prot = 0; uint nextLen = 0;
            WD.WinDivertHelperParsePacket(p, avail, &ip4, &ip6, &prot, null, null, &tcp, &udp, null, null, &next, &nextLen);
            proto = prot;
            lport = 0;
            src4 = dst4 = 0;
            if (ip4 != null)
            {
                src4 = (uint)(ip4[12] << 24 | ip4[13] << 16 | ip4[14] << 8 | ip4[15]);
                dst4 = (uint)(ip4[16] << 24 | ip4[17] << 16 | ip4[18] << 8 | ip4[19]);
            }
            byte* th = tcp != null ? tcp : udp;
            if (th != null)
                lport = outbound ? (th[0] << 8) | th[1] : (th[2] << 8) | th[3];
            if (next != null && next > p) return (int)(next - p);
            if (ip4 == null && ip6 == null) return 0;
            return (int)avail;
        }

        // ================= hotspot =================

        bool HotspotActive
        {
            get { return _hsAdapter || Clock.ElapsedMilliseconds - Math.Max(_seenFdown, _seenFup) < 10000; }
        }

        bool InHotspotNet(uint ip) { return ip != 0 && (ip & _hsMask) == _hsNet; }

        /// <summary>Records that a hotspot packet was seen at layer src and says whether this layer
        /// is the one that should count/shape that direction.</summary>
        bool HotspotTake(int src, bool upload)
        {
            long now = Clock.ElapsedMilliseconds;
            if (src == SRC_NET) { if (upload) _seenNup = now; else _seenNdown = now; }
            else { if (upload) _seenFup = now; else _seenFdown = now; }
            if (upload) return src == SRC_FWD || now - _seenFup > 3000;
            return src == SRC_NET || now - _seenNdown > 3000;
        }

        /// <summary>Unowned network-layer traffic while sharing is on = hotspot devices (NAT).</summary>
        AppInfo ResolveNet(int proto, int lport, bool outbound, out bool take)
        {
            take = true;
            AppInfo app = Resolve(proto, lport);
            if (app == UnknownApp && HotspotActive)
            {
                app = HotspotApp;
                take = HotspotTake(SRC_NET, outbound);
            }
            return app;
        }

        void DetectHotspot()
        {
            uint scope = 0xC0A88901; // 192.168.137.1
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"))
                {
                    var v = k == null ? null : k.GetValue("ScopeAddress") as string;
                    IPAddress ip;
                    if (v != null && IPAddress.TryParse(v.Trim(), out ip) && ip.GetAddressBytes().Length == 4) scope = ToUint(ip);
                }
            }
            catch { }
            bool found = false;
            uint mask = 0xFFFFFF00;
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    if (ToUint(ua.Address) != scope) continue;
                    found = true;
                    try { if (ua.IPv4Mask != null && ToUint(ua.IPv4Mask) != 0) mask = ToUint(ua.IPv4Mask); } catch { }
                }
            }
            _hsMask = mask;
            _hsNet = scope & mask;
            _hsAdapter = found;
        }

        static uint ToUint(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        }

        void ForwardSniffLoop()
        {
            var buf = new byte[1 << 20];
            var addr = new byte[WD.ADDR_SIZE * WD.BATCH_MAX];
            fixed (byte* pb = buf, pa = addr)
            {
                while (_running)
                {
                    uint recvLen = 0, addrLen = (uint)addr.Length;
                    if (!WD.WinDivertRecvEx(_fwdSniff, pb, (uint)buf.Length, &recvLen, 0, pa, &addrLen, IntPtr.Zero))
                    {
                        int e = Marshal.GetLastWin32Error();
                        if (!_running || e == 232 || e == 6 || e == 995) break;
                        continue;
                    }
                    bool counting = !_fwdDivertActive;
                    int n = (int)(addrLen / WD.ADDR_SIZE);
                    byte* p = pb, end = pb + recvLen;
                    for (int i = 0; i < n && p < end; i++)
                    {
                        int proto, lport; uint s4, d4;
                        int len = Parse(p, (uint)(end - p), false, out proto, out lport, out s4, out d4);
                        if (len <= 0) break;
                        p += len;
                        if (s4 == 0 && d4 == 0) continue;
                        bool upload = !InHotspotNet(d4);
                        if (HotspotTake(SRC_FWD, upload) && counting) Count(HotspotApp, upload, len);
                    }
                }
            }
        }

        // ================= threads =================

        void FlowLoop()
        {
            var addr = new byte[WD.ADDR_SIZE];
            fixed (byte* pa = addr)
            {
                while (_running)
                {
                    if (!WD.WinDivertRecv(_flow, null, 0, null, pa))
                    {
                        int e = Marshal.GetLastWin32Error();
                        if (!_running || e == 232 || e == 6 || e == 995) break;
                        continue;
                    }
                    uint bits = *(uint*)(pa + 8);
                    if (((bits >> 8) & 0xFF) != WD.EVENT_FLOW_ESTABLISHED) continue;
                    if (((bits >> 18) & 1) != 0) continue; // loopback
                    uint pid = *(uint*)(pa + 32);
                    int lport = *(ushort*)(pa + 68);
                    byte proto = pa[72];
                    if (pid == 0) continue;
                    if (proto == 6) _tcpPid[lport] = pid;
                    else if (proto == 17) _udpPid[lport] = pid;
                    try { AppForPid(pid); } catch { }
                }
            }
        }

        void SniffLoop()
        {
            var buf = new byte[1 << 20];
            var addr = new byte[WD.ADDR_SIZE * WD.BATCH_MAX];
            fixed (byte* pb = buf, pa = addr)
            {
                while (_running)
                {
                    uint recvLen = 0, addrLen = (uint)addr.Length;
                    if (!WD.WinDivertRecvEx(_sniff, pb, (uint)buf.Length, &recvLen, 0, pa, &addrLen, IntPtr.Zero))
                    {
                        int e = Marshal.GetLastWin32Error();
                        if (!_running || e == 232 || e == 6 || e == 995) break;
                        continue;
                    }
                    if (_divertActive) continue; // the shaping path does the counting
                    int n = (int)(addrLen / WD.ADDR_SIZE);
                    byte* p = pb, end = pb + recvLen;
                    for (int i = 0; i < n && p < end; i++)
                    {
                        byte* a = pa + i * WD.ADDR_SIZE;
                        bool outbound = ((*(uint*)(a + 8)) >> 17 & 1) != 0;
                        int proto, lport;
                        int len = Parse(p, (uint)(end - p), outbound, out proto, out lport);
                        if (len <= 0) break;
                        bool take;
                        AppInfo app = ResolveNet(proto, lport, outbound, out take);
                        if (take) Count(app, outbound, len);
                        p += len;
                    }
                }
            }
        }

        void DivertLoop(object state) { DivertCore((IntPtr)state, false); }
        void ForwardDivertLoop(object state) { DivertCore((IntPtr)state, true); }

        void DivertCore(IntPtr h, bool forward)
        {
            var buf = new byte[1 << 20];
            var addr = new byte[WD.ADDR_SIZE * WD.BATCH_MAX];
            var sbuf = new byte[1 << 20];
            var saddr = new byte[WD.ADDR_SIZE * WD.BATCH_MAX];
            fixed (byte* pb = buf, pa = addr, psb = sbuf, psa = saddr)
            {
                while (true)
                {
                    uint recvLen = 0, addrLen = (uint)addr.Length;
                    if (!WD.WinDivertRecvEx(h, pb, (uint)buf.Length, &recvLen, 0, pa, &addrLen, IntPtr.Zero))
                    {
                        int e = Marshal.GetLastWin32Error();
                        if (e == 232 || e == 6 || e == 995) break; // shut down
                        continue;
                    }
                    int n = (int)(addrLen / WD.ADDR_SIZE);
                    byte* p = pb, end = pb + recvLen;
                    uint sOff = 0; int sCnt = 0;
                    Bucket gDown = _gDown, gUp = _gUp;

                    for (int i = 0; i < n && p < end; i++)
                    {
                        byte* a = pa + i * WD.ADDR_SIZE;
                        bool outbound = ((*(uint*)(a + 8)) >> 17 & 1) != 0;
                        int proto, lport; uint s4, d4;
                        int len = Parse(p, (uint)(end - p), outbound, out proto, out lport, out s4, out d4);
                        if (len <= 0) break;

                        AppInfo app; bool take;
                        if (forward)
                        {
                            app = HotspotApp;
                            outbound = !InHotspotNet(d4);
                            take = (s4 != 0 || d4 != 0) && HotspotTake(SRC_FWD, outbound);
                        }
                        else app = ResolveNet(proto, lport, outbound, out take);

                        if (!take)
                        {
                            // another layer handles this packet: pass it through untouched and uncounted
                            Buffer.MemoryCopy(p, psb + sOff, sbuf.Length - sOff, len);
                            Buffer.MemoryCopy(a, psa + sCnt * WD.ADDR_SIZE, WD.ADDR_SIZE, WD.ADDR_SIZE);
                            sOff += (uint)len; sCnt++;
                            p += len;
                            continue;
                        }
                        Shaping s = app.Shape;
                        if (s != null && s.Block)
                        {
                            Interlocked.Increment(ref app.BlockedPackets);
                            p += len;
                            continue;
                        }
                        Bucket b = outbound ? (s != null && s.Up != null ? s.Up : gUp)
                                            : (s != null && s.Down != null ? s.Down : gDown);
                        if (b == null)
                        {
                            // pass straight through (batched)
                            Buffer.MemoryCopy(p, psb + sOff, sbuf.Length - sOff, len);
                            Buffer.MemoryCopy(a, psa + sCnt * WD.ADDR_SIZE, WD.ADDR_SIZE, WD.ADDR_SIZE);
                            sOff += (uint)len; sCnt++;
                            Count(app, outbound, len);
                        }
                        else
                        {
                            var q = new QPacket { Data = new byte[len], Addr = new byte[WD.ADDR_SIZE], Handle = h, App = app, Outbound = outbound };
                            Marshal.Copy((IntPtr)p, q.Data, 0, len);
                            Marshal.Copy((IntPtr)a, q.Addr, 0, WD.ADDR_SIZE);
                            b.Push(q);
                        }
                        p += len;
                    }
                    if (sCnt > 0)
                        WD.WinDivertSendEx(h, psb, sOff, null, 0, psa, (uint)(sCnt * WD.ADDR_SIZE), IntPtr.Zero);
                }
            }

            // drain anything still queued in buckets, then close
            Bucket[] act = _active;
            foreach (var b in act) b.FlushAll();
            lock (_retired) { foreach (var kv in _retired) kv.Key.FlushAll(); _retired.Clear(); }
            WD.WinDivertClose(h);
        }

        void SendQueued(QPacket q)
        {
            fixed (byte* d = q.Data, a = q.Addr)
            {
                if (WD.WinDivertSend(q.Handle, d, (uint)q.Data.Length, null, a))
                    Count(q.App, q.Outbound, q.Data.Length);
            }
        }

        void SchedulerLoop()
        {
            var sw = Stopwatch.StartNew();
            double last = 0;
            while (_running)
            {
                if (!_divertActive) { Thread.Sleep(50); last = sw.Elapsed.TotalSeconds; continue; }
                Thread.Sleep(1);
                double now = sw.Elapsed.TotalSeconds;
                double dt = now - last; last = now;
                if (dt > 0.25) dt = 0.25;
                try
                {
                    Bucket[] act = _active;
                    for (int i = 0; i < act.Length; i++) act[i].Tick(dt);
                    lock (_retired)
                    {
                        if (_retired.Count > 0)
                        {
                            var t = DateTime.UtcNow;
                            foreach (var kv in _retired) kv.Key.FlushAll();
                            _retired.RemoveAll(kv => kv.Value < t);
                        }
                    }
                }
                catch { }
            }
        }

        void TableLoop()
        {
            var sw = Stopwatch.StartNew();
            long lastFull = -100000, lastClean = 0, lastHs = 0;
            while (_running)
            {
                Thread.Sleep(200);
                long ms = sw.ElapsedMilliseconds;
                bool requested = Interlocked.Exchange(ref _refreshRequested, 0) == 1;
                if (!requested && ms - lastFull < 2000) continue;
                bool full = ms - lastFull >= 2000;
                try
                {
                    var conns = NetTables.Snapshot(_tcpPid, _udpPid, full && WantConnections);
                    if (full)
                    {
                        lastFull = ms;
                        if (WantConnections) Connections = conns;
                        var perPid = new Dictionary<uint, int>();
                        foreach (var c in conns)
                        {
                            if (c.State == "Listening") continue;
                            int v; perPid.TryGetValue(c.Pid, out v); perPid[c.Pid] = v + 1;
                        }
                        var counts = new Dictionary<AppInfo, int>();
                        foreach (var kv in perPid)
                        {
                            var app = AppForPid(kv.Key);
                            int v; counts.TryGetValue(app, out v); counts[app] = v + kv.Value;
                        }
                        foreach (var app in _apps.Values)
                        {
                            int v; counts.TryGetValue(app, out v); app.Connections = v;
                        }
                    }
                    if (ms - lastClean > 10000) { lastClean = ms; CleanDeadPids(); }
                    if (full && ms - lastHs >= 5000) { lastHs = ms; DetectHotspot(); }
                }
                catch { }
            }
        }

        void CleanDeadPids()
        {
            var alive = new HashSet<uint>();
            foreach (var p in Process.GetProcesses()) { alive.Add((uint)p.Id); p.Dispose(); }
            foreach (var kv in _pidApp.ToArray())
            {
                if (alive.Contains(kv.Key)) continue;
                AppInfo removed;
                _pidApp.TryRemove(kv.Key, out removed);
                if (removed != null) lock (removed.Pids) removed.Pids.Remove(kv.Key);
            }
            for (int i = 0; i < 65536; i++)
            {
                if (_tcpPid[i] != 0 && !alive.Contains(_tcpPid[i])) _tcpPid[i] = 0;
                if (_udpPid[i] != 0 && !alive.Contains(_udpPid[i])) _udpPid[i] = 0;
            }
        }

        // ================= rules =================

        Shaping BuildShape(string key, Dictionary<string, Rule> rules, Bucket gDown, Bucket gUp, List<Bucket> collect)
        {
            Rule r;
            if (!rules.TryGetValue(key, out r)) return null;
            var s = new Shaping { Block = r.Block };
            if (!r.Block)
            {
                if (r.DownLimit > 0) { s.Down = new Bucket(r.DownLimit, SendQueued) { Next = gDown }; if (collect != null) collect.Add(s.Down); }
                if (r.UpLimit > 0) { s.Up = new Bucket(r.UpLimit, SendQueued) { Next = gUp }; if (collect != null) collect.Add(s.Up); }
            }
            return s;
        }

        /// <summary>Applies the rule set. Returns false (with LastError) if the shaping driver handle failed.</summary>
        public bool ApplyRules(Config cfg)
        {
            lock (_rulesLock)
            {
                var dict = new Dictionary<string, Rule>();
                if (!cfg.RulesPaused && cfg.Rules != null)
                    foreach (var r in cfg.Rules)
                        if (r != null && !r.Disabled && (r.Block || r.DownLimit > 0 || r.UpLimit > 0) && r.Key != null)
                            dict[r.Key] = r;

                bool paused = cfg.RulesPaused;
                Bucket gDown = !paused && cfg.GlobalDown > 0 ? new Bucket(cfg.GlobalDown, SendQueued) : null;
                Bucket gUp = !paused && cfg.GlobalUp > 0 ? new Bucket(cfg.GlobalUp, SendQueued) : null;

                var list = new List<Bucket>();
                foreach (var app in _apps.Values)
                    app.Shape = BuildShape(app.Key, dict, gDown, gUp, list);
                if (gDown != null) list.Add(gDown);
                if (gUp != null) list.Add(gUp);

                Bucket[] old = _active;
                _rules = dict;
                _gDown = gDown; _gUp = gUp;
                _active = list.ToArray();
                lock (_retired)
                {
                    var exp = DateTime.UtcNow.AddSeconds(3);
                    foreach (var b in old) _retired.Add(new KeyValuePair<Bucket, DateTime>(b, exp));
                }

                bool need = dict.Count > 0 || gDown != null || gUp != null;
                if (need && !_divertActive) return StartDivert();
                if (!need && _divertActive) StopDivert();
                return true;
            }
        }

        bool StartDivert()
        {
            IntPtr h;
            try { h = WD.WinDivertOpen(NetFilter, WD.LAYER_NETWORK, 1000, 0); }
            catch (Exception ex) { LastError = "Could not start shaping: " + ex.Message; return false; }
            if (!WD.IsValid(h))
            {
                LastError = "Could not start shaping: " + WD.Explain(Marshal.GetLastWin32Error());
                return false;
            }
            WD.WinDivertSetParam(h, WD.PARAM_QUEUE_LENGTH, 16384);
            WD.WinDivertSetParam(h, WD.PARAM_QUEUE_SIZE, 16 * 1024 * 1024);
            WD.WinDivertSetParam(h, WD.PARAM_QUEUE_TIME, 4000);
            Win32.timeBeginPeriod(1);
            _divert = h;
            _divertActive = true;
            _divertThread = new Thread(DivertLoop) { IsBackground = true, Name = "nw-divert", Priority = ThreadPriority.Highest };
            _divertThread.Start(h);

            // forwarded (hotspot) traffic — optional; monitoring still works if this fails
            IntPtr fh = IntPtr.Zero;
            try { fh = WD.WinDivertOpen("ip", WD.LAYER_NETWORK_FORWARD, 1000, 0); } catch { }
            if (WD.IsValid(fh))
            {
                WD.WinDivertSetParam(fh, WD.PARAM_QUEUE_LENGTH, 16384);
                WD.WinDivertSetParam(fh, WD.PARAM_QUEUE_SIZE, 16 * 1024 * 1024);
                _fwdDivert = fh;
                _fwdDivertActive = true;
                _fwdDivertThread = new Thread(ForwardDivertLoop) { IsBackground = true, Name = "nw-fwd-divert", Priority = ThreadPriority.Highest };
                _fwdDivertThread.Start(fh);
            }
            LastError = null;
            return true;
        }

        Thread StopDivert()
        {
            if (!_divertActive) return null;
            _divertActive = false;
            IntPtr h = _divert;
            _divert = IntPtr.Zero;
            WD.WinDivertShutdown(h, WD.SHUTDOWN_RECV); // thread drains, flushes and closes the handle
            if (_fwdDivertActive)
            {
                _fwdDivertActive = false;
                IntPtr fh = _fwdDivert;
                _fwdDivert = IntPtr.Zero;
                WD.WinDivertShutdown(fh, WD.SHUTDOWN_RECV);
                _fwdDivertThread = null;
            }
            Thread t = _divertThread;
            _divertThread = null;
            Win32.timeEndPeriod(1);
            return t;
        }

        public void ResetCounters()
        {
            foreach (var a in _apps.Values)
            {
                Interlocked.Exchange(ref a.Down, 0); Interlocked.Exchange(ref a.Up, 0);
                Interlocked.Exchange(ref a.BlockedPackets, 0); Interlocked.Exchange(ref a.DroppedPackets, 0);
                a.PrevDown = 0; a.PrevUp = 0;
            }
            Interlocked.Exchange(ref TotalDown, 0); Interlocked.Exchange(ref TotalUp, 0);
        }
    }
}
