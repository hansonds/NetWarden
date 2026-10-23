using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace NetWarden
{
    /// <summary>P/Invoke surface for WinDivert 2.2 (signed packet-capture driver).</summary>
    internal static unsafe class WD
    {
        public const int LAYER_NETWORK = 0;
        public const int LAYER_NETWORK_FORWARD = 1;
        public const int LAYER_FLOW = 2;

        public const ulong FLAG_SNIFF = 0x0001;
        public const ulong FLAG_RECV_ONLY = 0x0004;

        public const int PARAM_QUEUE_LENGTH = 0;
        public const int PARAM_QUEUE_TIME = 1;
        public const int PARAM_QUEUE_SIZE = 2;

        public const int SHUTDOWN_RECV = 1;
        public const int SHUTDOWN_BOTH = 3;

        public const int ADDR_SIZE = 80;      // sizeof(WINDIVERT_ADDRESS)
        public const int BATCH_MAX = 255;

        public const int EVENT_FLOW_ESTABLISHED = 1;

        const string Dll = "WinDivert.dll";

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecv(IntPtr h, byte* pPacket, uint packetLen, uint* pRecvLen, byte* pAddr);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecvEx(IntPtr h, byte* pPacket, uint packetLen, uint* pRecvLen, ulong flags,
            byte* pAddr, uint* pAddrLen, IntPtr lpOverlapped);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSend(IntPtr h, byte* pPacket, uint packetLen, uint* pSendLen, byte* pAddr);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSendEx(IntPtr h, byte* pPacket, uint packetLen, uint* pSendLen, ulong flags,
            byte* pAddr, uint addrLen, IntPtr lpOverlapped);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertShutdown(IntPtr h, int how);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertClose(IntPtr h);

        [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSetParam(IntPtr h, int param, ulong value);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertHelperParsePacket(byte* pPacket, uint packetLen,
            byte** ppIpHdr, byte** ppIpv6Hdr, byte* pProtocol, byte** ppIcmpHdr, byte** ppIcmpv6Hdr,
            byte** ppTcpHdr, byte** ppUdpHdr, byte** ppData, uint* pDataLen, byte** ppNext, uint* pNextLen);

        public static bool IsValid(IntPtr h) { return h != IntPtr.Zero && h != new IntPtr(-1); }

        public static string Explain(int err)
        {
            switch (err)
            {
                case 2: return "The WinDivert driver file (WinDivert64.sys) was not found.";
                case 5: return "Access denied. Please run NetWarden as Administrator.";
                case 577: return "Windows refused the driver signature. If 'Memory integrity' or a strict security policy is on, the driver may be blocked.";
                case 1058: return "The WinDivert driver service is disabled.";
                case 1275: return "The driver was blocked from loading (often by antivirus or Windows security policy).";
                case 1753: return "The Windows 'Base Filtering Engine' service is not running.";
                case 654: return "An incompatible version of the WinDivert driver is already loaded (another app is using it). Reboot and try again.";
                case 87: return "Invalid filter or parameter.";
                case 193: return "This PC's architecture is not supported (WinDivert needs 64-bit x86 Windows).";
                default: return "WinDivert error " + err + ".";
            }
        }
    }

    internal sealed class ConnInfo
    {
        public uint Pid;
        public bool Udp;
        public string Local;
        public string Remote;
        public string State;
    }

    /// <summary>Snapshots of the Windows TCP/UDP tables (port → process mapping and connection lists).</summary>
    internal static unsafe class NetTables
    {
        const int AF_INET = 2, AF_INET6 = 23;
        const int TCP_TABLE_OWNER_PID_ALL = 5;
        const int UDP_TABLE_OWNER_PID = 1;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTable, ref int size, bool order, int af, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedUdpTable(IntPtr pTable, ref int size, bool order, int af, int tableClass, uint reserved);

        static readonly string[] TcpStates = { "?", "Closed", "Listening", "SYN sent", "SYN received", "Established",
            "FIN wait 1", "FIN wait 2", "Close wait", "Closing", "Last ACK", "Time wait", "Delete" };

        static int Port(uint raw) { return (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)); }

        static IntPtr Fetch(bool tcp, int af)
        {
            int size = 0;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                IntPtr buf = size > 0 ? Marshal.AllocHGlobal(size) : IntPtr.Zero;
                uint r = tcp ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                             : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
                if (r == 0 && buf != IntPtr.Zero) return buf;
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                if (r != 122 /*ERROR_INSUFFICIENT_BUFFER*/) return IntPtr.Zero;
                size += 4096;
            }
            return IntPtr.Zero;
        }

        static string V4(uint addr, int port) { return new IPAddress(addr).ToString() + ":" + port; }

        static string V6(byte* a, uint scope, int port)
        {
            var b = new byte[16];
            for (int i = 0; i < 16; i++) b[i] = a[i];
            var ip = new IPAddress(b);
            return "[" + ip + "]:" + port;
        }

        /// <summary>Fills port→pid maps and returns the current connection list.</summary>
        public static List<ConnInfo> Snapshot(uint[] tcpPid, uint[] udpPid, bool wantConns)
        {
            var list = new List<ConnInfo>(wantConns ? 512 : 0);

            // TCP IPv4: 24-byte rows
            IntPtr t = Fetch(true, AF_INET);
            if (t != IntPtr.Zero)
            {
                try
                {
                    byte* p = (byte*)t;
                    int n = *(int*)p; uint* row = (uint*)(p + 4);
                    for (int i = 0; i < n; i++, row += 6)
                    {
                        uint state = row[0], pid = row[5];
                        if (pid == 0) continue;
                        int lp = Port(row[2]);
                        tcpPid[lp] = pid;
                        if (wantConns)
                            list.Add(new ConnInfo
                            {
                                Pid = pid, Udp = false, Local = V4(row[1], lp),
                                Remote = state == 2 ? "—" : V4(row[3], Port(row[4])),
                                State = state < TcpStates.Length ? TcpStates[state] : "?"
                            });
                    }
                }
                finally { Marshal.FreeHGlobal(t); }
            }

            // TCP IPv6: 56-byte rows
            t = Fetch(true, AF_INET6);
            if (t != IntPtr.Zero)
            {
                try
                {
                    byte* p = (byte*)t;
                    int n = *(int*)p; byte* row = p + 4;
                    for (int i = 0; i < n; i++, row += 56)
                    {
                        uint lport = *(uint*)(row + 20), rport = *(uint*)(row + 44);
                        uint state = *(uint*)(row + 48), pid = *(uint*)(row + 52);
                        if (pid == 0) continue;
                        int lp = Port(lport);
                        tcpPid[lp] = pid;
                        if (wantConns)
                            list.Add(new ConnInfo
                            {
                                Pid = pid, Udp = false, Local = V6(row, 0, lp),
                                Remote = state == 2 ? "—" : V6(row + 24, 0, Port(rport)),
                                State = state < TcpStates.Length ? TcpStates[state] : "?"
                            });
                    }
                }
                finally { Marshal.FreeHGlobal(t); }
            }

            // UDP IPv4: 12-byte rows
            t = Fetch(false, AF_INET);
            if (t != IntPtr.Zero)
            {
                try
                {
                    byte* p = (byte*)t;
                    int n = *(int*)p; uint* row = (uint*)(p + 4);
                    for (int i = 0; i < n; i++, row += 3)
                    {
                        uint pid = row[2];
                        if (pid == 0) continue;
                        int lp = Port(row[1]);
                        udpPid[lp] = pid;
                        if (wantConns)
                            list.Add(new ConnInfo { Pid = pid, Udp = true, Local = V4(row[0], lp), Remote = "*", State = "Open" });
                    }
                }
                finally { Marshal.FreeHGlobal(t); }
            }

            // UDP IPv6: 28-byte rows
            t = Fetch(false, AF_INET6);
            if (t != IntPtr.Zero)
            {
                try
                {
                    byte* p = (byte*)t;
                    int n = *(int*)p; byte* row = p + 4;
                    for (int i = 0; i < n; i++, row += 28)
                    {
                        uint lport = *(uint*)(row + 20), pid = *(uint*)(row + 24);
                        if (pid == 0) continue;
                        int lp = Port(lport);
                        udpPid[lp] = pid;
                        if (wantConns)
                            list.Add(new ConnInfo { Pid = pid, Udp = true, Local = V6(row, 0, lp), Remote = "*", State = "Open" });
                    }
                }
                finally { Marshal.FreeHGlobal(t); }
            }
            return list;
        }
    }

    internal static class ProcInfo
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

        public static string GetPath(uint pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        public static string GetName(uint pid)
        {
            try { using (var p = Process.GetProcessById((int)pid)) return p.ProcessName + ".exe"; }
            catch { return null; }
        }

        public static string FriendlyName(string path)
        {
            string file = Path.GetFileName(path);
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                string d = (vi.FileDescription ?? "").Trim();
                if (file.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) return "Windows Services (svchost)";
                if (d.Length > 1 && d.Length < 60) return d;
            }
            catch { }
            return file;
        }
    }

    internal static class Win32
    {
        [DllImport("winmm.dll")] public static extern uint timeBeginPeriod(uint ms);
        [DllImport("winmm.dll")] public static extern uint timeEndPeriod(uint ms);

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        public static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string path);

        public static void DarkTitleBar(IntPtr hwnd)
        {
            try
            {
                int on = 1;
                if (DwmSetWindowAttribute(hwnd, 20, ref on, 4) != 0) DwmSetWindowAttribute(hwnd, 19, ref on, 4);
                int corner = 2; // DWMWCP_ROUND
                DwmSetWindowAttribute(hwnd, 33, ref corner, 4);
            }
            catch { }
        }
    }
}
