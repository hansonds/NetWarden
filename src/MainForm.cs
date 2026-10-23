using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace NetWarden
{
    internal sealed class MainForm : Form
    {
        readonly TrafficEngine _engine;
        readonly Config _cfg;
        readonly EventWaitHandle _showEvent;
        bool _startHidden, _exiting, _loadingPanel, _trayTipShown;

        // header
        Label _lblTotDown, _lblTotUp;
        TextBox _search;
        Button _btnPause;
        TrafficGraph _graph;
        // list
        GridView _list;
        readonly AppComparer _comparer;
        readonly Dictionary<string, Image> _icons = new Dictionary<string, Image>();
        double _maxRate = 1;
        // detail
        Panel _detail, _detailBody;
        Label _placeholder, _detName, _detPath, _detDown, _detUp, _detStats, _connTitle;
        PictureBox _detIcon;
        CheckBox _chkDown, _chkUp, _chkBlock;
        SpeedInput _numDown, _numUp;
        Button _btnClearRule, _btnOpenFolder;
        GridView _conns;
        AppInfo _selected;
        // status
        Label _lblStatus, _lblMode;
        // tray
        NotifyIcon _tray;
        ToolStripMenuItem _trayPause;

        readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer { Interval = 1000 };
        readonly Stopwatch _clock = Stopwatch.StartNew();
        double _lastTick;
        long _prevTotDown, _prevTotUp;

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, string l);

        public MainForm(TrafficEngine engine, Config cfg, bool startHidden, EventWaitHandle showEvent)
        {
            _engine = engine; _cfg = cfg; _startHidden = startHidden; _showEvent = showEvent;
            Theme.Init();
            _comparer = new AppComparer(this);

            Text = "NetWarden";
            Icon = AppIcon.Create(32);
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.UI;
            AutoScaleMode = AutoScaleMode.None;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(Theme.S(1220), Theme.S(740));
            MinimumSize = new Size(Theme.S(860), Theme.S(520));
            Theme.DarkenWindow(this);

            BuildList();
            BuildDetail();
            BuildStatus();
            BuildGraph();
            BuildHeader();
            BuildTray();

            _timer.Tick += (s, e) => Tick();
            _lastTick = _clock.Elapsed.TotalSeconds;

            if (!_engine.ApplyRules(_cfg)) SetStatus(_engine.LastError, true);

            var waiter = new Thread(() =>
            {
                while (true)
                {
                    try { _showEvent.WaitOne(); } catch { return; }
                    try { BeginInvoke((Action)ShowFromTray); } catch { }
                }
            }) { IsBackground = true };
            waiter.Start();
        }

        protected override void SetVisibleCore(bool value)
        {
            if (_startHidden)
            {
                _startHidden = false;
                if (!IsHandleCreated) CreateHandle();
                value = false;
                _timer.Start();
            }
            base.SetVisibleCore(value);
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            _timer.Start();
            Tick();
        }

        // ============================================================ layout

        void BuildHeader()
        {
            var header = new Panel { Dock = DockStyle.Top, Height = Theme.S(64), BackColor = Theme.Panel };
            header.Paint += (s, e) => { using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, 0, header.Height - 1, header.Width, header.Height - 1); };

            var logo = new PictureBox { Image = AppIcon.CreateBitmap(Theme.S(28)), SizeMode = PictureBoxSizeMode.CenterImage, Size = new Size(Theme.S(32), Theme.S(32)), Location = new Point(Theme.S(16), Theme.S(16)) };
            var title = Theme.MakeLabel("NetWarden", Theme.Title, Theme.Text);
            title.Location = new Point(Theme.S(54), Theme.S(18));

            _lblTotDown = Theme.MakeLabel("↓ 0 B/s", Theme.Big, Theme.Down);
            _lblTotDown.Location = new Point(Theme.S(210), Theme.S(15));
            _lblTotUp = Theme.MakeLabel("↑ 0 B/s", Theme.Big, Theme.Up);
            _lblTotUp.Location = new Point(Theme.S(370), Theme.S(15));

            var right = new FlowLayoutPanel
            {
                Dock = DockStyle.Right, FlowDirection = FlowDirection.RightToLeft, AutoSize = true, WrapContents = false,
                Padding = new Padding(0, Theme.S(16), Theme.S(12), 0), BackColor = Color.Transparent
            };

            var btnMenu = Theme.MakeButton("☰", 40);
            var menu = BuildMainMenu();
            btnMenu.Click += (s, e) => menu.Show(btnMenu, new Point(btnMenu.Width - menu.Width, btnMenu.Height));

            _btnPause = Theme.MakeButton("Pause rules", 110);
            _btnPause.Click += (s, e) => SetPaused(!_cfg.RulesPaused);

            var btnGlobal = Theme.MakeButton("Global limits", 116);
            btnGlobal.Click += (s, e) => EditGlobalLimits();

            var btnRules = Theme.MakeButton("Rules", 76);
            btnRules.Click += (s, e) => ShowRules();

            _search = new TextBox
            {
                BorderStyle = BorderStyle.FixedSingle, BackColor = Theme.Panel2, ForeColor = Theme.Text, Font = Theme.UI,
                Width = Theme.S(190), Margin = new Padding(Theme.S(3), Theme.S(4), Theme.S(8), 0)
            };
            _search.HandleCreated += (s, e) => { try { SendMessage(_search.Handle, 0x1501, (IntPtr)1, "Search apps…"); } catch { } };
            _search.TextChanged += (s, e) => RefreshList();

            foreach (var b in new Control[] { btnMenu, _btnPause, btnGlobal, btnRules }) b.Margin = new Padding(Theme.S(4), 0, 0, 0);
            right.Controls.AddRange(new Control[] { btnMenu, _btnPause, btnGlobal, btnRules, _search });

            header.Controls.Add(right);
            header.Controls.AddRange(new Control[] { logo, title, _lblTotDown, _lblTotUp });
            Controls.Add(header);
            UpdatePauseButton();
        }

        ContextMenuStrip BuildMainMenu()
        {
            var m = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), Font = Theme.UI, ShowImageMargin = false, ShowCheckMargin = true };
            var startup = new ToolStripMenuItem("Start with Windows");
            var tray = new ToolStripMenuItem("Close button minimizes to tray") { Checked = !_cfg.ExitOnClose };
            var idle = new ToolStripMenuItem("Show idle apps") { Checked = _cfg.ShowIdle };
            m.Opening += (s, e) => { startup.Checked = AutoStart.IsEnabled(); };
            startup.Click += (s, e) =>
            {
                bool want = !startup.Checked;
                if (!AutoStart.Set(want)) MessageBox.Show(this, "Could not update the startup task.", "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            tray.Click += (s, e) => { _cfg.ExitOnClose = tray.Checked; tray.Checked = !_cfg.ExitOnClose; _cfg.Save(); };
            idle.Click += (s, e) => { _cfg.ShowIdle = !_cfg.ShowIdle; idle.Checked = _cfg.ShowIdle; _cfg.Save(); RefreshList(); };
            m.Items.Add(startup);
            m.Items.Add(tray);
            m.Items.Add(idle);
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("Reset traffic counters", null, (s, e) => { _engine.ResetCounters(); _prevTotDown = _prevTotUp = 0; RefreshList(); });
            m.Items.Add("Open settings folder", null, (s, e) => { Directory.CreateDirectory(Config.Dir); Process.Start("explorer.exe", "\"" + Config.Dir + "\""); });
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("About NetWarden", null, (s, e) => MessageBox.Show(this,
                "NetWarden " + Program.Version + "\n\nLightweight per-app bandwidth monitor, limiter and blocker for Windows.\nPacket engine: WinDivert 2.2 (signed driver, loaded only while NetWarden runs).",
                "About", MessageBoxButtons.OK, MessageBoxIcon.Information));
            m.Items.Add("Exit", null, (s, e) => ExitApp());
            return m;
        }

        void BuildGraph()
        {
            _graph = new TrafficGraph { Dock = DockStyle.Top, Height = Theme.S(124) };
            Controls.Add(_graph);
        }

        void BuildStatus()
        {
            var bar = new Panel { Dock = DockStyle.Bottom, Height = Theme.S(28), BackColor = Theme.Panel };
            bar.Paint += (s, e) => { using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, 0, 0, bar.Width, 0); };
            _lblStatus = new Label { Dock = DockStyle.Fill, ForeColor = Theme.Dim, Font = Theme.Small, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(Theme.S(12), 0, 0, 0) };
            _lblMode = new Label { Dock = DockStyle.Right, AutoSize = false, Width = Theme.S(360), ForeColor = Theme.Dim, Font = Theme.Small, TextAlign = ContentAlignment.MiddleRight, Padding = new Padding(0, 0, Theme.S(12), 0) };
            bar.Controls.Add(_lblStatus);
            bar.Controls.Add(_lblMode);
            Controls.Add(bar);
            SetStatus("Monitoring all network traffic.", false);
        }

        void BuildList()
        {
            _list = new GridView { Dock = DockStyle.Fill, FillColumn = 6, RowHeight = Theme.S(34), Sortable = true,
                EmptyText = "Waiting for network activity…" };
            _list.AddColumn("APPLICATION", 224, false);
            _list.AddColumn("DOWNLOAD", 104, true);
            _list.AddColumn("UPLOAD", 104, true);
            _list.AddColumn("TOTAL ↓", 84, true);
            _list.AddColumn("TOTAL ↑", 84, true);
            _list.AddColumn("CONNS", 66, true);
            _list.AddColumn("RULE", 140, false);
            _list.SortColumn = _cfg.SortColumn >= 0 && _cfg.SortColumn < 7 ? _cfg.SortColumn : 1;
            _list.SortAsc = _cfg.SortAsc;
            _list.CustomCell = DrawAppCell;
            _list.HeaderClick += col =>
            {
                if (_list.SortColumn == col) _list.SortAsc = !_list.SortAsc;
                else { _list.SortColumn = col; _list.SortAsc = col == 0 || col == 6; }
                _cfg.SortColumn = _list.SortColumn; _cfg.SortAsc = _list.SortAsc;
                RefreshList();
            };
            _list.SelectionChanged += (s, e) =>
            {
                var app = _list.Selected as AppInfo;
                if (app != _selected) { _selected = app; ShowDetail(); }
            };
            var listMenu = BuildListMenu();
            _list.RowContextMenu += (row, pt) => ShowListMenu(listMenu, row as AppInfo, pt);
            var wrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(Theme.S(16), Theme.S(8), Theme.S(8), Theme.S(8)), BackColor = Theme.Bg };
            wrap.Controls.Add(_list);
            Controls.Add(wrap);
        }

        AppInfo _menuApp;
        ToolStripMenuItem _miLimitDown, _miLimitUp, _miBlock, _miClear, _miOpen, _miCopy;
        ToolStripSeparator _miSep1, _miSep2;

        ContextMenuStrip BuildListMenu()
        {
            var m = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), Font = Theme.UI, ShowImageMargin = false, ShowCheckMargin = false };
            _miLimitDown = new ToolStripMenuItem("Limit download…", null, (s, e) => MenuLimit(true));
            _miLimitUp = new ToolStripMenuItem("Limit upload…", null, (s, e) => MenuLimit(false));
            _miBlock = new ToolStripMenuItem("Block internet access", null, (s, e) => MenuToggleBlock());
            _miClear = new ToolStripMenuItem("Remove rule", null, (s, e) => MenuRemoveRule());
            _miOpen = new ToolStripMenuItem("Open file location", null, (s, e) => OpenFolder(_menuApp));
            _miCopy = new ToolStripMenuItem("Copy path", null, (s, e) =>
            {
                if (_menuApp == null || _menuApp.Path == null) return;
                try { Clipboard.SetText(_menuApp.Path); SetStatus("Copied: " + _menuApp.Path, false); } catch { }
            });
            _miSep1 = new ToolStripSeparator();
            _miSep2 = new ToolStripSeparator();
            m.Items.AddRange(new ToolStripItem[] { _miLimitDown, _miLimitUp, _miBlock, _miSep1, _miClear, _miSep2, _miOpen, _miCopy });
            foreach (ToolStripItem it in m.Items) { it.ForeColor = Theme.Text; it.Enabled = true; }
            return m;
        }

        void ShowListMenu(ContextMenuStrip m, AppInfo app, Point pt)
        {
            if (app == null) return;
            _menuApp = app;
            if (_selected != app) { _selected = app; ShowDetail(); }
            bool can = CanRule(app);
            var r = _cfg.Find(app.Key);
            bool blocked = r != null && r.Block;
            _miLimitDown.Visible = _miLimitUp.Visible = _miBlock.Visible = can;
            _miBlock.Text = blocked ? "Unblock internet access" : "Block internet access";
            _miBlock.ForeColor = blocked ? Theme.Text : Theme.Danger;
            _miClear.Visible = r != null;
            _miSep1.Visible = can && r != null;
            _miOpen.Visible = _miCopy.Visible = app.Path != null;
            _miSep2.Visible = (can || r != null) && app.Path != null;
            if (!can && r == null && app.Path == null) return; // nothing applies (e.g. Unknown)
            foreach (ToolStripItem it in m.Items) it.Enabled = true;
            m.Show(_list, pt);
        }

        void MenuLimit(bool download)
        {
            var app = _menuApp;
            if (app == null || !CanRule(app)) return;
            if (_selected != app) { _selected = app; _list.Selected = app; ShowDetail(); }
            var chk = download ? _chkDown : _chkUp;
            var num = download ? _numDown : _numUp;
            if (!chk.Checked) chk.Checked = true;   // applies the rule immediately
            num.SelectNumber();
        }

        void MenuToggleBlock()
        {
            var app = _menuApp;
            if (app == null || !CanRule(app)) return;
            var r = _cfg.Find(app.Key);
            if (r == null) { r = new Rule { Key = app.Key, Path = app.Path, Name = app.Name }; _cfg.Rules.Add(r); }
            r.Block = !r.Block;
            r.Disabled = false;
            if (!r.Block && r.DownLimit <= 0 && r.UpLimit <= 0) _cfg.Rules.Remove(r);
            ApplyAll();
            if (_selected == app) ShowDetail();
            SetStatus((r.Block ? "Blocked: " : "Unblocked: ") + app.Name, false);
        }

        void MenuRemoveRule()
        {
            var app = _menuApp;
            if (app == null) return;
            var r = _cfg.Find(app.Key);
            if (r != null) _cfg.Rules.Remove(r);
            ApplyAll();
            if (_selected == app) ShowDetail();
            SetStatus("Rule removed: " + app.Name, false);
        }

        void BuildDetail()
        {
            _detail = new Panel { Dock = DockStyle.Right, Width = Theme.S(340), BackColor = Theme.Panel };
            _detail.Paint += (s, e) => { using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, 0, 0, 0, _detail.Height); };

            _placeholder = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Theme.Dim, Font = Theme.UI,
                Text = "Select an application\nto see its connections and\nset speed limits or block it."
            };

            _detailBody = new Panel { BackColor = Theme.Panel, Visible = false, Size = new Size(_detail.Width, Theme.S(640)) };
            int pad = Theme.S(18), W = _detail.Width, y;

            _detIcon = new PictureBox { Location = new Point(pad, pad), Size = new Size(Theme.S(36), Theme.S(36)), SizeMode = PictureBoxSizeMode.Zoom };
            _detName = new Label { Location = new Point(pad + Theme.S(48), pad - Theme.S(2)), Size = new Size(W - pad * 2 - Theme.S(48), Theme.S(24)), Font = Theme.Name, ForeColor = Theme.Text, AutoEllipsis = true, Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
            _detPath = new Label { Location = new Point(pad + Theme.S(48), pad + Theme.S(22)), Size = new Size(W - pad * 2 - Theme.S(48), Theme.S(18)), Font = Theme.Small, ForeColor = Theme.Dim, AutoEllipsis = true, Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
            y = pad + Theme.S(54);
            _detDown = Theme.MakeLabel("↓ 0 B/s", Theme.Big, Theme.Down); _detDown.Location = new Point(pad - Theme.S(3), y);
            _detUp = Theme.MakeLabel("↑ 0 B/s", Theme.Big, Theme.Up); _detUp.Location = new Point(pad + Theme.S(150), y);
            y += Theme.S(36);
            _detStats = new Label { Location = new Point(pad, y), Size = new Size(W - pad * 2, Theme.S(34)), Font = Theme.Small, ForeColor = Theme.Dim, Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
            y += Theme.S(44);

            var rulesTitle = Theme.MakeLabel("RULES", Theme.SmallBold, Theme.Dim); rulesTitle.Location = new Point(pad, y);
            y += Theme.S(24);
            _chkDown = Theme.MakeCheck("Limit download"); _chkDown.Location = new Point(pad, y + Theme.S(3));
            _numDown = new SpeedInput(512); _numDown.Location = new Point(Theme.S(158), y);
            y += Theme.S(34);
            _chkUp = Theme.MakeCheck("Limit upload"); _chkUp.Location = new Point(pad, y + Theme.S(3));
            _numUp = new SpeedInput(128); _numUp.Location = new Point(Theme.S(158), y);
            y += Theme.S(36);
            _chkBlock = Theme.MakeCheck("Block all internet access"); _chkBlock.Location = new Point(pad, y);
            _chkBlock.ForeColor = Theme.Danger;
            y += Theme.S(36);
            _btnClearRule = Theme.MakeButton("Remove rule", 120); _btnClearRule.Location = new Point(pad, y);
            _btnOpenFolder = Theme.MakeButton("Open location", 120); _btnOpenFolder.Location = new Point(pad + Theme.S(130), y);
            _btnClearRule.Click += (s, e) => ClearRule();
            _btnOpenFolder.Click += (s, e) => OpenFolder();
            y += Theme.S(48);

            _connTitle = Theme.MakeLabel("CONNECTIONS", Theme.SmallBold, Theme.Dim); _connTitle.Location = new Point(pad, y);
            y += Theme.S(22);
            _conns = new GridView
            {
                Location = new Point(pad, y), Size = new Size(W - pad * 2, Theme.S(200)),
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right | AnchorStyles.Bottom,
                CellFont = Theme.Small, FillColumn = 1, RowHeight = Theme.S(24), HeaderHeight = Theme.S(24),
                RowBg1 = Theme.Panel, RowBg2 = Theme.Panel2, HeaderBg = Theme.Panel, BackColor = Theme.Panel,
                EmptyText = "No open connections"
            };
            _conns.AddColumn("PROTO", 60, false);
            _conns.AddColumn("REMOTE", 170, false);
            _conns.AddColumn("STATE", 84, false);
            _conns.TextOf = ConnText;
            _conns.CustomCell = DrawConnCell;

            EventHandler changed = (s, e) => { _numDown.Enabled = _chkDown.Checked; _numUp.Enabled = _chkUp.Checked; ApplyFromPanel(); };
            _chkDown.CheckedChanged += changed;
            _chkUp.CheckedChanged += changed;
            _chkBlock.CheckedChanged += changed;
            _numDown.ValueChanged += (s, e) => { if (_chkDown.Checked) ApplyFromPanel(); };
            _numUp.ValueChanged += (s, e) => { if (_chkUp.Checked) ApplyFromPanel(); };

            _detailBody.Controls.AddRange(new Control[] { _detIcon, _detName, _detPath, _detDown, _detUp, _detStats, rulesTitle,
                _chkDown, _numDown, _chkUp, _numUp, _chkBlock, _btnClearRule, _btnOpenFolder, _connTitle, _conns });
            _detailBody.Resize += (s, e) => { _conns.Height = Math.Max(Theme.S(60), _detailBody.ClientSize.Height - _conns.Top - pad); };
            _detailBody.Dock = DockStyle.Fill;
            _detail.Controls.Add(_detailBody);
            _detail.Controls.Add(_placeholder);
            Controls.Add(_detail);
        }

        void BuildTray()
        {
            var m = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), Font = Theme.UI, ShowImageMargin = false, ShowCheckMargin = true };
            m.Items.Add(new ToolStripMenuItem("Open NetWarden", null, (s, e) => ShowFromTray()) { Font = Theme.UIBold });
            _trayPause = new ToolStripMenuItem("Pause all rules", null, (s, e) => SetPaused(!_cfg.RulesPaused));
            m.Items.Add(_trayPause);
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("Exit", null, (s, e) => ExitApp());
            _tray = new NotifyIcon { Icon = AppIcon.Create(16), Text = "NetWarden", Visible = true, ContextMenuStrip = m };
            _tray.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) ShowFromTray(); };
        }

        // ============================================================ drawing

        Image IconFor(AppInfo app)
        {
            Image img;
            if (_icons.TryGetValue(app.Key, out img)) return img;
            img = null;
            if (app.Path != null)
            {
                try
                {
                    using (var ic = Icon.ExtractAssociatedIcon(app.Path))
                        if (ic != null) img = new Bitmap(ic.ToBitmap(), Theme.S(20), Theme.S(20));
                }
                catch { }
            }
            if (img == null) img = GenericIcon(app);
            _icons[app.Key] = img;
            return img;
        }

        static Image GenericIcon(AppInfo app)
        {
            int s = Theme.S(20);
            var bmp = new Bitmap(s, s);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                if (app.Key == "hotspot")
                {
                    // Wi-Fi style glyph: dot + three arcs, in a soft green disc
                    using (var b = new SolidBrush(Theme.Alpha(Theme.Good, 50))) g.FillEllipse(b, 0, 0, s - 1, s - 1);
                    float cx = s / 2f, cy = s * 0.72f, w = Math.Max(1.4f, s * 0.08f);
                    using (var p = new Pen(Theme.Good, w) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                        for (int k = 1; k <= 3; k++)
                        {
                            float r = s * 0.13f * k;
                            g.DrawArc(p, cx - r, cy - r, r * 2, r * 2, 225, 90);
                        }
                    using (var b = new SolidBrush(Theme.Good)) g.FillEllipse(b, cx - w, cy - w, w * 2, w * 2);
                    return bmp;
                }
                Color c = app.Key == "unknown" ? Theme.Dim : app.Key == "system" ? Theme.Accent : Theme.Hex(0x7C86A0);
                using (var b = new SolidBrush(Theme.Alpha(c, 60))) g.FillEllipse(b, 1, 1, s - 3, s - 3);
                using (var p = new Pen(c, 1.5f)) g.DrawEllipse(p, 1, 1, s - 3, s - 3);
                string ch = app.Key == "unknown" ? "?" : app.Key == "system" ? "S" : (app.FileName ?? "?").Substring(0, 1).ToUpperInvariant();
                TextRenderer.DrawText(g, ch, Theme.SmallBold, new Rectangle(0, 0, s, s), Theme.Text, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
            return bmp;
        }

        bool DrawAppCell(GridCell e)
        {
            var app = e.Row as AppInfo;
            if (app == null) return false;
            var g = e.G;
            var b = e.Bounds;
            int pad = Theme.S(8);
            var flagsL = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.Left | TextFormatFlags.SingleLine;
            var flagsR = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.Right | TextFormatFlags.SingleLine;
            var rule = _cfg.RulesPaused ? null : _cfg.Find(app.Key);
            if (rule != null && rule.Disabled) rule = null;

            switch (e.Col)
            {
                case 0:
                {
                    var icon = IconFor(app);
                    int iy = b.Y + (b.Height - icon.Height) / 2;
                    g.DrawImage(icon, b.X + pad + Theme.S(2), iy, icon.Width, icon.Height);
                    var r = new Rectangle(b.X + pad + Theme.S(32), b.Y, b.Width - pad * 2 - Theme.S(32), b.Height);
                    Color c = app.Special && app.Key != "hotspot" ? Theme.Dim : Theme.Text;
                    if (rule != null && rule.Block) c = Theme.Danger;
                    TextRenderer.DrawText(g, app.Name, Theme.UI, r, c, flagsL);
                    return true;
                }
                case 1:
                case 2:
                {
                    double rate = e.Col == 1 ? app.RateDown : app.RateUp;
                    Color c = e.Col == 1 ? Theme.Down : Theme.Up;
                    if (rate > 0)
                    {
                        int w = (int)((b.Width - pad * 2) * Math.Min(1.0, rate / _maxRate));
                        if (w > 0)
                            using (var br = new SolidBrush(Theme.Alpha(c, 38)))
                                g.FillRectangle(br, b.Right - pad - w, b.Y + Theme.S(7), w, b.Height - Theme.S(14));
                    }
                    TextRenderer.DrawText(g, Theme.Rate(rate), Theme.UI, new Rectangle(b.X + pad, b.Y, b.Width - pad * 2, b.Height), rate > 0 ? c : Theme.Dim, flagsR);
                    return true;
                }
                case 3:
                case 4:
                {
                    long v = e.Col == 3 ? Interlocked.Read(ref app.Down) : Interlocked.Read(ref app.Up);
                    TextRenderer.DrawText(g, Theme.Bytes(v), Theme.UI, new Rectangle(b.X + pad, b.Y, b.Width - pad * 2, b.Height), Theme.Dim, flagsR);
                    return true;
                }
                case 5:
                    TextRenderer.DrawText(g, app.Connections > 0 ? app.Connections.ToString() : "", Theme.UI,
                        new Rectangle(b.X + pad, b.Y, b.Width - pad * 2, b.Height), Theme.Dim, flagsR);
                    return true;
                case 6:
                {
                    if (rule == null) return true;
                    string text; Color c;
                    if (rule.Block) { text = "⛔ Blocked"; c = Theme.Danger; }
                    else
                    {
                        var parts = new List<string>();
                        if (rule.DownLimit > 0) parts.Add("↓ " + Theme.Limit(rule.DownLimit, rule.DownUnit));
                        if (rule.UpLimit > 0) parts.Add("↑ " + Theme.Limit(rule.UpLimit, rule.UpUnit));
                        text = string.Join("   ", parts); c = Theme.Good;
                    }
                    var r = new Rectangle(b.X + pad, b.Y + Theme.S(6), Math.Min(b.Width - pad * 2, TextRenderer.MeasureText(text, Theme.Small).Width + Theme.S(16)), b.Height - Theme.S(12));
                    using (var path = TrafficGraph.Rounded(r, Theme.S(4)))
                    using (var br = new SolidBrush(Theme.Alpha(c, 34)))
                    {
                        g.SmoothingMode = SmoothingMode.AntiAlias;
                        g.FillPath(br, path);
                        g.SmoothingMode = SmoothingMode.None;
                    }
                    TextRenderer.DrawText(g, text, Theme.Small, r, c, TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
                    return true;
                }
            }
            return false;
        }

        static string ConnText(object row, int col)
        {
            var c = (ConnInfo)row;
            if (col == 0) return c.Udp ? "UDP" : "TCP";
            if (col == 1) return c.Udp ? c.Local + " (bound)" : c.State == "Listening" ? c.Local + " (listening)" : c.Remote;
            return c.State;
        }

        bool DrawConnCell(GridCell e)
        {
            var r = new Rectangle(e.Bounds.X + Theme.S(6), e.Bounds.Y, e.Bounds.Width - Theme.S(10), e.Bounds.Height);
            Color c = Theme.Dim;
            if (e.Col == 1) c = Theme.Text;
            if (e.Col == 2 && e.Text == "Established") c = Theme.Good;
            TextRenderer.DrawText(e.G, e.Text, Theme.Small, r, c, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            return true;
        }

        // ============================================================ refresh

        void Tick()
        {
            double now = _clock.Elapsed.TotalSeconds;
            double dt = Math.Max(0.2, now - _lastTick);
            _lastTick = now;

            long td = Interlocked.Read(ref _engine.TotalDown), tu = Interlocked.Read(ref _engine.TotalUp);
            double rd = Math.Max(0, (td - _prevTotDown) / dt), ru = Math.Max(0, (tu - _prevTotUp) / dt);
            _prevTotDown = td; _prevTotUp = tu;

            double max = 1;
            foreach (var a in _engine.Apps)
            {
                long d = Interlocked.Read(ref a.Down), u = Interlocked.Read(ref a.Up);
                a.RateDown = Math.Max(0, (d - a.PrevDown) / dt);
                a.RateUp = Math.Max(0, (u - a.PrevUp) / dt);
                a.PrevDown = d; a.PrevUp = u;
                if (a.RateDown > 0 || a.RateUp > 0) a.LastActive = DateTime.UtcNow;
                max = Math.Max(max, Math.Max(a.RateDown, a.RateUp));
            }
            _maxRate = max;

            string tipText = "NetWarden\n↓ " + Theme.RateOrZero(rd) + "   ↑ " + Theme.RateOrZero(ru);
            _tray.Text = tipText.Length > 63 ? tipText.Substring(0, 63) : tipText;

            _engine.WantConnections = Visible && WindowState != FormWindowState.Minimized;
            if (!_engine.WantConnections) { _graph.Push(rd, ru); return; } // hidden: keep it cheap

            _lblTotDown.Text = "↓ " + Theme.RateOrZero(rd);
            _lblTotUp.Text = "↑ " + Theme.RateOrZero(ru);
            _lblTotUp.Left = Math.Max(_lblTotDown.Right + Theme.S(24), Theme.S(370));
            _graph.Push(rd, ru);
            RefreshList();
            UpdateDetailLive();

            int nRules = _cfg.Rules.Count(r => !r.Disabled);
            string mode = _cfg.RulesPaused ? "Rules paused" : _engine.ShapingActive ? "Shaping active" : "Monitoring";
            _lblMode.Text = mode + "  ·  " + nRules + " rule" + (nRules == 1 ? "" : "s") + "  ·  Session ↓ " + (Theme.Bytes(td) == "" ? "0 B" : Theme.Bytes(td)) + "  ↑ " + (Theme.Bytes(tu) == "" ? "0 B" : Theme.Bytes(tu));
            _lblMode.ForeColor = _cfg.RulesPaused ? Theme.Up : _engine.ShapingActive ? Theme.Good : Theme.Dim;
        }

        bool IsVisibleApp(AppInfo a, string filter)
        {
            if (filter.Length > 0)
                return (a.Name ?? "").IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0 ||
                       (a.Path ?? "").IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
            if (a == _selected) return true;
            bool hasTraffic = Interlocked.Read(ref a.Down) + Interlocked.Read(ref a.Up) > 0;
            if (_cfg.ShowIdle) return hasTraffic || a.Connections > 0 || _cfg.Find(a.Key) != null;
            return a.RateDown > 0 || a.RateUp > 0 || a.Connections > 0 || _cfg.Find(a.Key) != null ||
                   (DateTime.UtcNow - a.LastActive).TotalSeconds < 60;
        }

        void RefreshList()
        {
            string filter = _search.Text.Trim();
            var apps = _engine.Apps.ToList();
            var visible = new HashSet<AppInfo>(apps.Where(a => IsVisibleApp(a, filter)));

            var rows = visible.ToList();
            rows.Sort(_comparer);
            _list.SetRows(rows.Cast<object>());
        }

        // ============================================================ detail panel

        static bool CanRule(AppInfo a) { return a != null && a.Key != "unknown"; }

        void ShowDetail()
        {
            var app = _selected;
            _placeholder.Visible = app == null;
            _detailBody.Visible = app != null;
            if (app == null) return;

            _loadingPanel = true;
            try
            {
                _detIcon.Image = IconFor(app);
                _detName.Text = app.Name;
                _detPath.Text = app.Path ?? (app.Key == "unknown" ? "Traffic that couldn't be matched to a process yet" : app.FileName);
                var r = _cfg.Find(app.Key);
                _chkDown.Checked = r != null && r.DownLimit > 0;
                _chkUp.Checked = r != null && r.UpLimit > 0;
                _chkBlock.Checked = r != null && r.Block;
                if (r != null && r.DownLimit > 0) _numDown.SetValue(r.DownLimit, r.DownUnit);
                if (r != null && r.UpLimit > 0) _numUp.SetValue(r.UpLimit, r.UpUnit);
                _numDown.Enabled = _chkDown.Checked;
                _numUp.Enabled = _chkUp.Checked;
                bool can = CanRule(app);
                _chkDown.Enabled = _chkUp.Enabled = _chkBlock.Enabled = can;
                _btnClearRule.Enabled = r != null;
                _btnOpenFolder.Enabled = app.Path != null;
                _conns.SetRows(new object[0]);
            }
            finally { _loadingPanel = false; }
            UpdateDetailLive();
        }

        void UpdateDetailLive()
        {
            var app = _selected;
            if (app == null || !_detailBody.Visible) return;
            _detDown.Text = "↓ " + Theme.RateOrZero(app.RateDown);
            _detUp.Text = "↑ " + Theme.RateOrZero(app.RateUp);
            _detUp.Left = Math.Max(_detDown.Right + Theme.S(16), Theme.S(168));

            uint[] pids;
            lock (app.Pids) pids = app.Pids.ToArray();
            string down = Theme.Bytes(Interlocked.Read(ref app.Down)), up = Theme.Bytes(Interlocked.Read(ref app.Up));
            string stats = "Session total  ↓ " + (down == "" ? "0 B" : down) + "   ↑ " + (up == "" ? "0 B" : up);
            if (pids.Length > 0) stats += "\nPID " + string.Join(", ", pids.OrderBy(p => p).Take(8)) + (pids.Length > 8 ? " …" : "");
            long blocked = Interlocked.Read(ref app.BlockedPackets), dropped = Interlocked.Read(ref app.DroppedPackets);
            if (blocked > 0) stats += (pids.Length > 0 ? "  ·  " : "\n") + blocked.ToString("N0") + " packets blocked";
            else if (dropped > 0) stats += (pids.Length > 0 ? "  ·  " : "\n") + dropped.ToString("N0") + " packets shaped away";
            _detStats.Text = stats;

            // connections
            var set = new HashSet<uint>(pids);
            var rows = _engine.Connections.Where(c => set.Contains(c.Pid))
                .OrderBy(c => c.Udp).ThenBy(c => c.State == "Established" ? 0 : c.State == "Listening" ? 2 : 1).ThenBy(c => c.Remote)
                .Take(300).ToList();
            _connTitle.Text = "CONNECTIONS (" + rows.Count + ")";
            _conns.SetRows(rows.Cast<object>());
        }

        void ApplyFromPanel()
        {
            if (_loadingPanel || _selected == null || !CanRule(_selected)) return;
            var app = _selected;
            var r = _cfg.Find(app.Key);
            bool any = _chkDown.Checked || _chkUp.Checked || _chkBlock.Checked;
            if (!any)
            {
                if (r != null) _cfg.Rules.Remove(r);
            }
            else
            {
                if (r == null) { r = new Rule { Key = app.Key, Path = app.Path, Name = app.Name }; _cfg.Rules.Add(r); }
                r.DownLimit = _chkDown.Checked ? _numDown.BytesPerSec : 0;
                r.UpLimit = _chkUp.Checked ? _numUp.BytesPerSec : 0;
                r.DownUnit = _numDown.UnitName;
                r.UpUnit = _numUp.UnitName;
                r.Block = _chkBlock.Checked;
                r.Disabled = false;
            }
            _btnClearRule.Enabled = _cfg.Find(app.Key) != null;
            ApplyAll();
        }

        void ClearRule()
        {
            if (_selected == null) return;
            var r = _cfg.Find(_selected.Key);
            if (r != null) _cfg.Rules.Remove(r);
            ApplyAll();
            ShowDetail();
        }

        void OpenFolder() { OpenFolder(_selected); }

        void OpenFolder(AppInfo app)
        {
            if (app == null || app.Path == null) return;
            try
            {
                if (File.Exists(app.Path))
                    Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + app.Path + "\"") { UseShellExecute = true });
                else
                    Process.Start(new ProcessStartInfo("explorer.exe", "\"" + Path.GetDirectoryName(app.Path) + "\"") { UseShellExecute = true });
            }
            catch (Exception ex) { SetStatus("Could not open folder: " + ex.Message, true); }
        }

        void ApplyAll()
        {
            bool ok = _engine.ApplyRules(_cfg);
            _cfg.Save();
            if (!ok) SetStatus(_engine.LastError, true);
            else if (_cfg.RulesPaused) SetStatus("Rules are paused — traffic is only being monitored.", false);
            else SetStatus("Rules applied.", false);
            UpdatePauseButton();
            _list.Invalidate();
        }

        void SetPaused(bool paused)
        {
            _cfg.RulesPaused = paused;
            ApplyAll();
        }

        void UpdatePauseButton()
        {
            if (_btnPause == null) return;
            _btnPause.Text = _cfg.RulesPaused ? "Resume rules" : "Pause rules";
            _btnPause.ForeColor = _cfg.RulesPaused ? Theme.Up : Theme.Text;
            if (_trayPause != null) _trayPause.Checked = _cfg.RulesPaused;
        }

        void SetStatus(string text, bool error)
        {
            if (_lblStatus == null) return;
            _lblStatus.Text = text ?? "";
            _lblStatus.ForeColor = error ? Theme.Danger : Theme.Dim;
        }

        void EditGlobalLimits()
        {
            using (var d = new GlobalLimitsDialog(_cfg.GlobalDown, _cfg.GlobalDownUnit, _cfg.GlobalUp, _cfg.GlobalUpUnit))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                _cfg.GlobalDown = d.Down;
                _cfg.GlobalUp = d.Up;
                _cfg.GlobalDownUnit = d.DownUnit;
                _cfg.GlobalUpUnit = d.UpUnit;
                ApplyAll();
            }
        }

        void ShowRules()
        {
            using (var d = new RulesDialog(_cfg))
            {
                d.ShowDialog(this);
                if (d.Changed) { ApplyAll(); ShowDetail(); }
            }
        }

        // ============================================================ window / tray

        void ShowFromTray()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
            Tick();
        }

        void ExitApp()
        {
            _exiting = true;
            Close();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_exiting && !_cfg.ExitOnClose && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                if (!_trayTipShown)
                {
                    _trayTipShown = true;
                    _tray.ShowBalloonTip(3000, "NetWarden is still running",
                        "Your rules stay active. Right-click the tray icon to exit.", ToolTipIcon.Info);
                }
                return;
            }
            _timer.Stop();
            _tray.Visible = false;
            _tray.Dispose();
            _cfg.Save();
            base.OnFormClosing(e);
        }

        sealed class AppComparer : IComparer<AppInfo>
        {
            readonly MainForm _f;
            public AppComparer(MainForm f) { _f = f; }

            public int Compare(AppInfo a, AppInfo b)
            {
                var _lv = _f._list;
                int c;
                switch (_lv.SortColumn)
                {
                    case 1: c = a.RateDown.CompareTo(b.RateDown); if (c == 0) c = Interlocked.Read(ref a.Down).CompareTo(Interlocked.Read(ref b.Down)); break;
                    case 2: c = a.RateUp.CompareTo(b.RateUp); if (c == 0) c = Interlocked.Read(ref a.Up).CompareTo(Interlocked.Read(ref b.Up)); break;
                    case 3: c = Interlocked.Read(ref a.Down).CompareTo(Interlocked.Read(ref b.Down)); break;
                    case 4: c = Interlocked.Read(ref a.Up).CompareTo(Interlocked.Read(ref b.Up)); break;
                    case 5: c = a.Connections.CompareTo(b.Connections); break;
                    default: c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); break;
                }
                if (!_lv.SortAsc) c = -c;
                if (c == 0) c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                return c;
            }
        }
    }

    // ================================================================ dialogs

    internal class DarkDialog : Form
    {
        public DarkDialog(string title, int w, int h)
        {
            Text = title;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(Theme.S(w), Theme.S(h));
            BackColor = Theme.Panel;
            ForeColor = Theme.Text;
            Font = Theme.UI;
            Icon = AppIcon.Create(32);
            Theme.DarkenWindow(this);
        }
    }

    internal sealed class GlobalLimitsDialog : DarkDialog
    {
        readonly CheckBox _cd, _cu;
        readonly SpeedInput _nd, _nu;
        public long Down, Up;
        public string DownUnit, UpUnit;

        public GlobalLimitsDialog(long down, string downUnit, long up, string upUnit) : base("Global limits", 390, 210)
        {
            int pad = Theme.S(20), y = pad;
            var info = new Label { Text = "Caps the combined speed of all applications.", Location = new Point(pad, y), AutoSize = true, ForeColor = Theme.Dim };
            y += Theme.S(34);
            _cd = Theme.MakeCheck("Total download"); _cd.Location = new Point(pad, y + Theme.S(3));
            _nd = new SpeedInput(2048); _nd.Location = new Point(Theme.S(196), y);
            if (down > 0) _nd.SetValue(down, downUnit);
            y += Theme.S(38);
            _cu = Theme.MakeCheck("Total upload"); _cu.Location = new Point(pad, y + Theme.S(3));
            _nu = new SpeedInput(1024); _nu.Location = new Point(Theme.S(196), y);
            if (up > 0) _nu.SetValue(up, upUnit);
            _cd.Checked = down > 0; _cu.Checked = up > 0;
            _nd.Enabled = _cd.Checked; _nu.Enabled = _cu.Checked;
            _cd.CheckedChanged += (s, e) => _nd.Enabled = _cd.Checked;
            _cu.CheckedChanged += (s, e) => _nu.Enabled = _cu.Checked;

            var ok = Theme.MakeButton("Save", 96); ok.Location = new Point(ClientSize.Width - pad - Theme.S(200), ClientSize.Height - pad - Theme.S(30));
            var cancel = Theme.MakeButton("Cancel", 96); cancel.Location = new Point(ClientSize.Width - pad - Theme.S(96), ok.Top);
            ok.BackColor = Theme.Accent; ok.FlatAppearance.BorderColor = Theme.Accent;
            ok.Click += (s, e) =>
            {
                Down = _cd.Checked ? _nd.BytesPerSec : 0;
                Up = _cu.Checked ? _nu.BytesPerSec : 0;
                DownUnit = _nd.UnitName; UpUnit = _nu.UnitName;
                DialogResult = DialogResult.OK;
            };
            cancel.Click += (s, e) => DialogResult = DialogResult.Cancel;
            AcceptButton = ok; CancelButton = cancel;
            Controls.AddRange(new Control[] { info, _cd, _nd, _cu, _nu, ok, cancel });
        }
    }

    internal sealed class RulesDialog : DarkDialog
    {
        readonly Config _cfg;
        readonly GridView _lv;
        public bool Changed;

        public RulesDialog(Config cfg) : base("Rules", 640, 400)
        {
            _cfg = cfg;
            int pad = Theme.S(16);
            _lv = new GridView
            {
                Location = new Point(pad, pad), Size = new Size(ClientSize.Width - pad * 2, ClientSize.Height - pad * 3 - Theme.S(30)),
                FillColumn = 0, RowHeight = Theme.S(30),
                EmptyText = "No rules yet. Select an app in the main window to add one."
            };
            _lv.AddColumn("APPLICATION", 240, false);
            _lv.AddColumn("DOWNLOAD", 100, false);
            _lv.AddColumn("UPLOAD", 100, false);
            _lv.AddColumn("STATUS", 100, false);
            _lv.TextOf = (row, col) =>
            {
                var r = (Rule)row;
                switch (col)
                {
                    case 0: return r.Name ?? Path.GetFileName(r.Path ?? r.Key);
                    case 1: return r.Block ? "—" : r.DownLimit > 0 ? Theme.Limit(r.DownLimit, r.DownUnit) : "unlimited";
                    case 2: return r.Block ? "—" : r.UpLimit > 0 ? Theme.Limit(r.UpLimit, r.UpUnit) : "unlimited";
                    default: return r.Disabled ? "Disabled" : r.Block ? "Blocked" : "Limited";
                }
            };
            _lv.CustomCell = e =>
            {
                var r = (Rule)e.Row;
                Color c = r.Disabled ? Theme.Dim : e.Col == 3 ? (r.Block ? Theme.Danger : Theme.Good) : e.Col == 0 ? Theme.Text : Theme.Dim;
                TextRenderer.DrawText(e.G, e.Text, Theme.UI, new Rectangle(e.Bounds.X + Theme.S(8), e.Bounds.Y, e.Bounds.Width - Theme.S(16), e.Bounds.Height), c,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
                return true;
            };

            var toggle = Theme.MakeButton("Enable / Disable", 140);
            var del = Theme.MakeButton("Delete", 90);
            var close = Theme.MakeButton("Close", 90);
            int by = ClientSize.Height - pad - Theme.S(30);
            toggle.Location = new Point(pad, by);
            del.Location = new Point(pad + Theme.S(150), by);
            close.Location = new Point(ClientSize.Width - pad - Theme.S(90), by);
            toggle.Click += (s, e) => { var r = _lv.Selected as Rule; if (r == null) return; r.Disabled = !r.Disabled; Changed = true; Fill(); };
            del.Click += (s, e) => { var r = _lv.Selected as Rule; if (r == null) return; _cfg.Rules.Remove(r); _lv.Selected = null; Changed = true; Fill(); };
            close.Click += (s, e) => Close();
            CancelButton = close;
            Controls.AddRange(new Control[] { _lv, toggle, del, close });
            Fill();
        }

        void Fill() { _lv.SetRows(_cfg.Rules.OrderBy(r => r.Name).Cast<object>()); }
    }

    /// <summary>The NetWarden logo, drawn in code (shield with download/upload arrows).</summary>
    internal static class AppIcon
    {
        [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);

        public static Bitmap CreateBitmap(int size)
        {
            var bmp = new Bitmap(size, size);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float s = size;
                var shield = new GraphicsPath();
                shield.AddBezier(s * 0.5f, s * 0.04f, s * 0.68f, s * 0.14f, s * 0.84f, s * 0.16f, s * 0.92f, s * 0.16f);
                shield.AddBezier(s * 0.92f, s * 0.16f, s * 0.94f, s * 0.58f, s * 0.78f, s * 0.82f, s * 0.5f, s * 0.97f);
                shield.AddBezier(s * 0.5f, s * 0.97f, s * 0.22f, s * 0.82f, s * 0.06f, s * 0.58f, s * 0.08f, s * 0.16f);
                shield.AddBezier(s * 0.08f, s * 0.16f, s * 0.16f, s * 0.16f, s * 0.32f, s * 0.14f, s * 0.5f, s * 0.04f);
                using (var br = new LinearGradientBrush(new RectangleF(0, 0, s, s), Theme.Hex(0x3B7BFF), Theme.Hex(0x1BC6E8), 60f))
                    g.FillPath(br, shield);
                float w = Math.Max(1.4f, s * 0.085f);
                using (var p = new Pen(Color.White, w) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                {
                    // down arrow (left)
                    g.DrawLine(p, s * 0.37f, s * 0.28f, s * 0.37f, s * 0.70f);
                    g.DrawLines(p, new[] { new PointF(s * 0.25f, s * 0.58f), new PointF(s * 0.37f, s * 0.70f), new PointF(s * 0.49f, s * 0.58f) });
                    // up arrow (right)
                    g.DrawLine(p, s * 0.63f, s * 0.70f, s * 0.63f, s * 0.28f);
                    g.DrawLines(p, new[] { new PointF(s * 0.51f, s * 0.40f), new PointF(s * 0.63f, s * 0.28f), new PointF(s * 0.75f, s * 0.40f) });
                }
            }
            return bmp;
        }

        public static Icon Create(int size)
        {
            using (var bmp = CreateBitmap(Theme.S(size)))
            {
                IntPtr h = bmp.GetHicon();
                var ic = (Icon)Icon.FromHandle(h).Clone();
                try { DestroyIcon(h); } catch { }
                return ic;
            }
        }
    }
}
