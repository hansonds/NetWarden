using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace NetWarden
{
    internal static class Theme
    {
        public static readonly Color Bg = Hex(0x0E1014);
        public static readonly Color Panel = Hex(0x15181F);
        public static readonly Color Panel2 = Hex(0x1C2029);
        public static readonly Color Row2 = Hex(0x12151B);
        public static readonly Color Border = Hex(0x2A2F3A);
        public static readonly Color Text = Hex(0xE7E9EE);
        public static readonly Color Dim = Hex(0x8A93A6);
        public static readonly Color Down = Hex(0x39A8FF);
        public static readonly Color Up = Hex(0xFF8B3D);
        public static readonly Color Danger = Hex(0xFF4D61);
        public static readonly Color Good = Hex(0x35D49A);
        public static readonly Color Select = Hex(0x22314C);
        public static readonly Color Accent = Hex(0x5B8CFF);

        public static readonly Font UI = new Font("Segoe UI", 9f);
        public static readonly Font UIBold = new Font("Segoe UI Semibold", 9f);
        public static readonly Font Small = new Font("Segoe UI", 8f);
        public static readonly Font SmallBold = new Font("Segoe UI Semibold", 7.75f);
        public static readonly Font Big = new Font("Segoe UI Semibold", 14f);
        public static readonly Font Title = new Font("Segoe UI Semibold", 13f);
        public static readonly Font Name = new Font("Segoe UI Semibold", 11f);

        public static float Scale = 1f;
        public static int S(int v) { return (int)Math.Round(v * Scale); }

        public static void Init()
        {
            using (var g = Graphics.FromHwnd(IntPtr.Zero)) Scale = g.DpiX / 96f;
        }

        public static Color Hex(int rgb) { return Color.FromArgb((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF); }
        public static Color Alpha(Color c, int a) { return Color.FromArgb(a, c); }

        public static string Rate(double b)
        {
            if (b < 1) return "";
            if (b < 1024) return b.ToString("0") + " B/s";
            if (b < 1048576) return (b / 1024).ToString(b < 10240 ? "0.0" : "0") + " KB/s";
            if (b < 1073741824) return (b / 1048576).ToString(b < 10485760 ? "0.00" : "0.0") + " MB/s";
            return (b / 1073741824).ToString("0.00") + " GB/s";
        }

        public static string RateOrZero(double b) { var s = Rate(b); return s.Length == 0 ? "0 B/s" : s; }

        public static string Bytes(long b)
        {
            if (b <= 0) return "";
            if (b < 1024) return b + " B";
            if (b < 1048576) return (b / 1024.0).ToString("0.0") + " KB";
            if (b < 1073741824) return (b / 1048576.0).ToString("0.0") + " MB";
            return (b / 1073741824.0).ToString("0.00") + " GB";
        }

        public static string Limit(long bps) { return Limit(bps, null); }

        public static string Limit(long bps, string unit)
        {
            var u = SpeedUnit.Find(unit);
            decimal v = bps / u.Factor;
            string num = v >= 100 || v == Math.Round(v) ? Math.Round(v).ToString("N0") : v.ToString(v >= 10 ? "0.#" : "0.##");
            return num + " " + u.Name;
        }

        public static Button MakeButton(string text, int width)
        {
            var b = new Button
            {
                Text = text, FlatStyle = FlatStyle.Flat, BackColor = Panel2, ForeColor = Text, Font = UI,
                Size = new Size(S(width), S(30)), Cursor = Cursors.Hand, UseVisualStyleBackColor = false
            };
            b.FlatAppearance.BorderColor = Border;
            b.FlatAppearance.MouseOverBackColor = Hex(0x262B36);
            b.FlatAppearance.MouseDownBackColor = Hex(0x2E3442);
            return b;
        }

        public static CheckBox MakeCheck(string text)
        {
            var c = new CheckBox
            {
                Text = text, FlatStyle = FlatStyle.Flat, ForeColor = Text, BackColor = Color.Transparent,
                Font = UI, AutoSize = true, Cursor = Cursors.Hand
            };
            c.FlatAppearance.BorderColor = Dim;
            c.FlatAppearance.CheckedBackColor = Accent;
            return c;
        }

        public static NumericUpDown MakeNumber()
        {
            return new NumericUpDown
            {
                Minimum = 1, Maximum = 10000000, Value = 512, Increment = 64, ThousandsSeparator = true,
                BackColor = Panel2, ForeColor = Text, BorderStyle = BorderStyle.FixedSingle, Font = UI,
                Width = S(108), TextAlign = HorizontalAlignment.Right
            };
        }

        public static Label MakeLabel(string text, Font f, Color c)
        {
            return new Label { Text = text, Font = f, ForeColor = c, AutoSize = true, BackColor = Color.Transparent };
        }

        public static void DarkenWindow(Form f)
        {
            f.HandleCreated += (s, e) => Win32.DarkTitleBar(f.Handle);
        }
    }

    internal sealed class SpeedUnit
    {
        public string Name;
        public decimal Factor;   // bytes per second for 1 unit
        public int Decimals;

        public static readonly SpeedUnit[] All =
        {
            new SpeedUnit { Name = "B/s",    Factor = 1m,          Decimals = 0 },
            new SpeedUnit { Name = "KB/s",   Factor = 1024m,       Decimals = 0 },
            new SpeedUnit { Name = "MB/s",   Factor = 1048576m,    Decimals = 2 },
            new SpeedUnit { Name = "GB/s",   Factor = 1073741824m, Decimals = 2 },
            new SpeedUnit { Name = "bit/s",  Factor = 0.125m,      Decimals = 0 },
            new SpeedUnit { Name = "Kbit/s", Factor = 125m,        Decimals = 0 },
            new SpeedUnit { Name = "Mbit/s", Factor = 125000m,     Decimals = 2 },
            new SpeedUnit { Name = "Gbit/s", Factor = 125000000m,  Decimals = 2 },
        };

        public static SpeedUnit Default { get { return All[1]; } }

        public static SpeedUnit Find(string name)
        {
            foreach (var u in All) if (u.Name == name) return u;
            return Default;
        }

        public override string ToString() { return Name; }
    }

    /// <summary>Number box + unit dropdown (B/s … Gbit/s, default KB/s), like NetLimiter's limit editor.</summary>
    internal sealed class SpeedInput : Panel
    {
        readonly NumericUpDown _num;
        readonly ComboBox _unit;
        bool _quiet;
        public event EventHandler ValueChanged;

        public SpeedInput(decimal defaultKb)
        {
            BackColor = Color.Transparent;
            Size = new Size(Theme.S(164), Theme.S(26));
            _num = Theme.MakeNumber();
            _num.Width = Theme.S(86);
            _num.Location = new Point(0, 0);
            _num.Value = defaultKb;
            _unit = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Panel2, ForeColor = Theme.Text, Font = Theme.UI,
                DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = Theme.S(20),
                Location = new Point(Theme.S(90), 0), Width = Theme.S(74), MaxDropDownItems = 8
            };
            _unit.Items.AddRange(SpeedUnit.All);
            _unit.SelectedItem = SpeedUnit.Default;
            _unit.DrawItem += DrawUnit;
            _unit.SelectedIndexChanged += UnitChanged;
            _num.ValueChanged += (s, e) => { if (!_quiet && ValueChanged != null) ValueChanged(this, EventArgs.Empty); };
            Controls.Add(_num);
            Controls.Add(_unit);
            ApplyDecimals(SpeedUnit.Default);
        }

        public SpeedUnit Unit { get { return (SpeedUnit)_unit.SelectedItem ?? SpeedUnit.Default; } }
        public string UnitName { get { return Unit.Name; } }

        /// <summary>Limit in bytes per second.</summary>
        public long BytesPerSec { get { return Math.Max(1, (long)Math.Round(_num.Value * Unit.Factor)); } }

        public void SetValue(long bytesPerSec, string unitName)
        {
            _quiet = true;
            try
            {
                var u = SpeedUnit.Find(unitName);
                _unit.SelectedItem = u;
                ApplyDecimals(u);
                SetNumber(bytesPerSec / u.Factor);
            }
            finally { _quiet = false; }
        }

        public void SelectNumber() { _num.Focus(); _num.Select(0, 30); }

        public new bool Enabled
        {
            get { return _num.Enabled; }
            set { _num.Enabled = value; _unit.Enabled = value; }
        }

        void SetNumber(decimal v)
        {
            v = Math.Round(v, _num.DecimalPlaces);
            if (v < _num.Minimum) v = _num.Minimum;
            if (v > _num.Maximum) v = _num.Maximum;
            _num.Value = v;
        }

        void ApplyDecimals(SpeedUnit u)
        {
            _num.DecimalPlaces = u.Decimals;
            _num.Minimum = u.Decimals > 0 ? 0.01m : 1m;
            _num.Increment = u.Decimals > 0 ? 0.5m : 64m;
        }

        SpeedUnit _lastUnit = SpeedUnit.Default;

        void UnitChanged(object sender, EventArgs e)
        {
            var u = Unit;
            if (!_quiet)
            {
                // keep the same real speed, shown in the new unit
                decimal bytes = _num.Value * _lastUnit.Factor;
                _quiet = true;
                try { ApplyDecimals(u); SetNumber(bytes / u.Factor); }
                finally { _quiet = false; }
                if (ValueChanged != null) ValueChanged(this, EventArgs.Empty);
            }
            _lastUnit = u;
        }

        static void DrawUnit(object sender, DrawItemEventArgs e)
        {
            var cb = (ComboBox)sender;
            bool sel = (e.State & DrawItemState.Selected) != 0 && (e.State & DrawItemState.ComboBoxEdit) == 0;
            Color bg = sel ? Theme.Accent : Theme.Panel2;
            using (var b = new SolidBrush(bg)) e.Graphics.FillRectangle(b, e.Bounds);
            if (e.Index < 0) return;
            TextRenderer.DrawText(e.Graphics, cb.Items[e.Index].ToString(), Theme.UI,
                new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height),
                cb.Enabled ? Theme.Text : Theme.Dim, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPrefix);
        }
    }

    internal sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
    {
        public DarkMenuRenderer() : base(new DarkColors()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? (e.Item.ForeColor == Theme.Danger ? Theme.Danger : Theme.Text) : Theme.Dim;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
        {
            var r = e.ImageRectangle;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var p = new Pen(Theme.Accent, Math.Max(2f, Theme.Scale * 1.8f)))
            {
                g.DrawLines(p, new[] {
                    new PointF(r.Left + r.Width * 0.2f, r.Top + r.Height * 0.52f),
                    new PointF(r.Left + r.Width * 0.42f, r.Top + r.Height * 0.74f),
                    new PointF(r.Left + r.Width * 0.82f, r.Top + r.Height * 0.28f) });
            }
        }

        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
        {
            e.ArrowColor = Theme.Dim;
            base.OnRenderArrow(e);
        }

        sealed class DarkColors : ProfessionalColorTable
        {
            public override Color ToolStripDropDownBackground { get { return Theme.Panel2; } }
            public override Color ImageMarginGradientBegin { get { return Theme.Panel2; } }
            public override Color ImageMarginGradientMiddle { get { return Theme.Panel2; } }
            public override Color ImageMarginGradientEnd { get { return Theme.Panel2; } }
            public override Color MenuBorder { get { return Theme.Border; } }
            public override Color MenuItemBorder { get { return Theme.Hex(0x2E3442); } }
            public override Color MenuItemSelected { get { return Theme.Hex(0x2A3040); } }
            public override Color MenuItemSelectedGradientBegin { get { return Theme.Hex(0x2A3040); } }
            public override Color MenuItemSelectedGradientEnd { get { return Theme.Hex(0x2A3040); } }
            public override Color SeparatorDark { get { return Theme.Border; } }
            public override Color SeparatorLight { get { return Theme.Border; } }
            public override Color CheckBackground { get { return Theme.Panel2; } }
            public override Color CheckSelectedBackground { get { return Theme.Hex(0x2A3040); } }
            public override Color CheckPressedBackground { get { return Theme.Hex(0x2A3040); } }
        }
    }

    internal sealed class GridCell
    {
        public Graphics G;
        public Rectangle Bounds;
        public object Row;
        public int Col, RowIndex;
        public bool Selected;
        public string Text;
    }

    /// <summary>Fully custom-drawn, double-buffered dark list (replaces the native ListView, which flickers
    /// and blanks rows when owner-drawn with live updates).</summary>
    internal sealed class GridView : Control
    {
        public sealed class Column { public string Title; public int Width; public bool Right; }

        public readonly List<Column> Columns = new List<Column>();
        public int FillColumn = -1;
        public int RowHeight = Theme.S(28);
        public int HeaderHeight = Theme.S(30);
        public bool Sortable;
        public int SortColumn = -1;
        public bool SortAsc = true;
        public string EmptyText = "";
        public Color RowBg1 = Theme.Bg, RowBg2 = Theme.Row2, HeaderBg = Theme.Panel;
        public Font CellFont = Theme.UI;
        public Func<object, int, string> TextOf;
        public Func<GridCell, bool> CustomCell;
        public event EventHandler SelectionChanged;
        public event Action<int> HeaderClick;
        public event Action<object, Point> RowContextMenu;

        List<object> _rows = new List<object>();
        object _selected;
        int _scroll, _hover = -1;
        bool _dragThumb;
        int _dragStartY, _dragStartScroll;
        readonly GridCell _cell = new GridCell();

        public GridView()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
        }

        public void AddColumn(string title, int width, bool right)
        {
            Columns.Add(new Column { Title = title, Width = Theme.S(width), Right = right });
        }

        public object Selected
        {
            get { return _selected; }
            set { if (!Equals(_selected, value)) { _selected = value; Invalidate(); if (SelectionChanged != null) SelectionChanged(this, EventArgs.Empty); } }
        }

        public int RowCount { get { return _rows.Count; } }

        public void SetRows(IEnumerable<object> rows)
        {
            _rows = new List<object>(rows);
            ClampScroll();
            Invalidate();
        }

        int ViewHeight { get { return Math.Max(0, ClientSize.Height - HeaderHeight); } }
        int ContentHeight { get { return _rows.Count * RowHeight; } }
        bool HasScroll { get { return ContentHeight > ViewHeight; } }
        int ScrollW { get { return HasScroll ? Theme.S(10) : 0; } }

        void ClampScroll()
        {
            int max = Math.Max(0, ContentHeight - ViewHeight);
            if (_scroll > max) _scroll = max;
            if (_scroll < 0) _scroll = 0;
        }

        int[] Widths()
        {
            var w = new int[Columns.Count];
            int used = 0;
            for (int i = 0; i < w.Length; i++) { w[i] = Columns[i].Width; if (i != FillColumn) used += w[i]; }
            if (FillColumn >= 0 && FillColumn < w.Length)
                w[FillColumn] = Math.Max(Theme.S(50), ClientSize.Width - ScrollW - used);
            return w;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            int W = ClientSize.Width - ScrollW;
            var widths = Widths();
            var flagsBase = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
            int pad = Theme.S(8);

            g.Clear(RowBg1);

            // rows
            g.SetClip(new Rectangle(0, HeaderHeight, ClientSize.Width, ViewHeight));
            int first = _scroll / RowHeight;
            for (int i = first; i < _rows.Count; i++)
            {
                int y = HeaderHeight + i * RowHeight - _scroll;
                if (y > ClientSize.Height) break;
                object row = _rows[i];
                bool sel = Equals(row, _selected);
                Color bg = sel ? Theme.Select : i == _hover ? Theme.Hex(0x1A1F29) : (i % 2 == 0 ? RowBg1 : RowBg2);
                using (var b = new SolidBrush(bg)) g.FillRectangle(b, 0, y, W, RowHeight);
                if (sel) using (var b = new SolidBrush(Theme.Accent)) g.FillRectangle(b, 0, y, Theme.S(3), RowHeight);

                int x = 0;
                for (int c = 0; c < widths.Length; c++)
                {
                    var r = new Rectangle(x, y, widths[c], RowHeight);
                    _cell.G = g; _cell.Bounds = r; _cell.Row = row; _cell.Col = c; _cell.RowIndex = i; _cell.Selected = sel;
                    _cell.Text = TextOf != null ? TextOf(row, c) : "";
                    if (CustomCell == null || !CustomCell(_cell))
                        TextRenderer.DrawText(g, _cell.Text ?? "", CellFont, new Rectangle(r.X + pad, r.Y, r.Width - pad * 2, r.Height),
                            c == 0 ? Theme.Text : Theme.Dim, flagsBase | (Columns[c].Right ? TextFormatFlags.Right : TextFormatFlags.Left));
                    x += widths[c];
                }
            }
            g.ResetClip();

            if (_rows.Count == 0 && EmptyText.Length > 0)
                TextRenderer.DrawText(g, EmptyText, Theme.UI, new Rectangle(0, HeaderHeight, W, Math.Max(RowHeight * 3, ViewHeight / 2)), Theme.Dim,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak);

            // header
            using (var b = new SolidBrush(HeaderBg)) g.FillRectangle(b, 0, 0, ClientSize.Width, HeaderHeight);
            using (var p = new Pen(Theme.Border)) g.DrawLine(p, 0, HeaderHeight - 1, ClientSize.Width, HeaderHeight - 1);
            int hx = 0;
            for (int c = 0; c < widths.Length; c++)
            {
                string t = Columns[c].Title;
                if (c == SortColumn) t = Columns[c].Right ? (SortAsc ? "▲ " : "▼ ") + t : t + (SortAsc ? " ▲" : " ▼");
                TextRenderer.DrawText(g, t, Theme.SmallBold, new Rectangle(hx + pad, 0, widths[c] - pad * 2, HeaderHeight),
                    c == SortColumn ? Theme.Text : Theme.Dim, flagsBase | (Columns[c].Right ? TextFormatFlags.Right : TextFormatFlags.Left));
                hx += widths[c];
            }

            // scrollbar
            if (HasScroll)
            {
                var th = Thumb();
                using (var b = new SolidBrush(_dragThumb ? Theme.Dim : Theme.Hex(0x3A4150)))
                using (var path = TrafficGraph.Rounded(th, Math.Max(2, th.Width / 2 - 1)))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.FillPath(b, path);
                    g.SmoothingMode = SmoothingMode.None;
                }
            }
        }

        Rectangle Thumb()
        {
            int track = ViewHeight - Theme.S(4);
            int h = Math.Max(Theme.S(24), (int)((long)track * ViewHeight / Math.Max(1, ContentHeight)));
            int maxScroll = Math.Max(1, ContentHeight - ViewHeight);
            int y = HeaderHeight + Theme.S(2) + (int)((long)(track - h) * _scroll / maxScroll);
            return new Rectangle(ClientSize.Width - Theme.S(8), y, Theme.S(6), h);
        }

        int RowAt(int y)
        {
            if (y < HeaderHeight) return -1;
            int i = (y - HeaderHeight + _scroll) / RowHeight;
            return i >= 0 && i < _rows.Count ? i : -1;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
            if (HasScroll && e.X >= ClientSize.Width - ScrollW && e.Y >= HeaderHeight)
            {
                var th = Thumb();
                if (th.Contains(new Point(th.X, e.Y))) { _dragThumb = true; _dragStartY = e.Y; _dragStartScroll = _scroll; }
                else { _scroll += (e.Y < th.Y ? -1 : 1) * ViewHeight; ClampScroll(); }
                Invalidate();
                return;
            }
            if (e.Y < HeaderHeight)
            {
                if (e.Button == MouseButtons.Left && Sortable)
                {
                    var w = Widths(); int x = 0;
                    for (int c = 0; c < w.Length; c++) { if (e.X < x + w[c]) { if (HeaderClick != null) HeaderClick(c); break; } x += w[c]; }
                }
                return;
            }
            int i = RowAt(e.Y);
            if (i >= 0) Selected = _rows[i];
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_dragThumb)
            {
                int track = ViewHeight - Theme.S(4);
                int h = Thumb().Height;
                int maxScroll = Math.Max(1, ContentHeight - ViewHeight);
                _scroll = _dragStartScroll + (int)((long)(e.Y - _dragStartY) * maxScroll / Math.Max(1, track - h));
                ClampScroll();
                Invalidate();
                return;
            }
            int hv = e.X < ClientSize.Width - ScrollW ? RowAt(e.Y) : -1;
            if (hv != _hover) { _hover = hv; Invalidate(); }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            if (_dragThumb) { _dragThumb = false; Invalidate(); return; }
            if (e.Button == MouseButtons.Right && e.X < ClientSize.Width - ScrollW)
            {
                int i = RowAt(e.Y);
                if (i >= 0)
                {
                    Selected = _rows[i];
                    if (RowContextMenu != null) RowContextMenu(_rows[i], e.Location);
                }
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hover != -1) { _hover = -1; Invalidate(); }
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            base.OnMouseWheel(e);
            _scroll -= e.Delta / 120 * RowHeight * 3;
            ClampScroll();
            Invalidate();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            ClampScroll();
        }

        protected override bool IsInputKey(Keys k) { return k == Keys.Up || k == Keys.Down || base.IsInputKey(k); }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (_rows.Count == 0 || (e.KeyCode != Keys.Up && e.KeyCode != Keys.Down)) return;
            int i = _selected == null ? -1 : _rows.IndexOf(_selected);
            i = Math.Max(0, Math.Min(_rows.Count - 1, i + (e.KeyCode == Keys.Down ? 1 : -1)));
            Selected = _rows[i];
            int top = i * RowHeight;
            if (top < _scroll) _scroll = top;
            else if (top + RowHeight > _scroll + ViewHeight) _scroll = top + RowHeight - ViewHeight;
            ClampScroll();
            Invalidate();
        }
    }

    /// <summary>Two-series area graph of total download/upload over the last two minutes.</summary>
    internal sealed class TrafficGraph : Control
    {
        const int N = 120;
        readonly double[] _down = new double[N], _up = new double[N];

        public TrafficGraph()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg;
        }

        public void Push(double down, double up)
        {
            Array.Copy(_down, 1, _down, 0, N - 1); _down[N - 1] = down;
            Array.Copy(_up, 1, _up, 0, N - 1); _up[N - 1] = up;
            Invalidate();
        }

        static double NiceMax(double v)
        {
            double min = 16 * 1024;
            if (v < min) return min;
            double p = Math.Pow(2, Math.Ceiling(Math.Log(v * 1.15, 2)));
            return p;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Theme.Bg);
            int pad = Theme.S(16);
            var area = new Rectangle(pad, Theme.S(26), Width - pad * 2, Height - Theme.S(26) - Theme.S(10));
            if (area.Width < 10 || area.Height < 10) return;

            using (var b = new SolidBrush(Theme.Panel))
            using (var path = Rounded(new Rectangle(pad - Theme.S(6), Theme.S(6), area.Width + Theme.S(12), Height - Theme.S(10)), Theme.S(8)))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.FillPath(b, path);
            }

            double max = 1;
            for (int i = 0; i < N; i++) max = Math.Max(max, Math.Max(_down[i], _up[i]));
            max = NiceMax(max);

            using (var grid = new Pen(Theme.Alpha(Theme.Border, 160)) { DashStyle = DashStyle.Dot })
                for (int i = 1; i <= 3; i++)
                {
                    int y = area.Top + area.Height * i / 4;
                    g.DrawLine(grid, area.Left, y, area.Right, y);
                }

            DrawSeries(g, area, _down, max, Theme.Down);
            DrawSeries(g, area, _up, max, Theme.Up);

            TextRenderer.DrawText(g, "Total traffic · last 2 minutes", Theme.SmallBold,
                new Point(area.Left, Theme.S(11)), Theme.Dim);
            string scale = "scale " + Theme.RateOrZero(max);
            var sz = TextRenderer.MeasureText(scale, Theme.Small);
            TextRenderer.DrawText(g, scale, Theme.Small, new Point(area.Right - sz.Width, Theme.S(11)), Theme.Dim);
            string legend = "■ Download   ■ Upload";
            var lsz = TextRenderer.MeasureText(legend, Theme.Small);
            int lx = area.Right - sz.Width - lsz.Width - Theme.S(16);
            TextRenderer.DrawText(g, "■ Download", Theme.Small, new Point(lx, Theme.S(11)), Theme.Down);
            TextRenderer.DrawText(g, "■ Upload", Theme.Small, new Point(lx + TextRenderer.MeasureText("■ Download   ", Theme.Small).Width, Theme.S(11)), Theme.Up);
        }

        static void DrawSeries(Graphics g, Rectangle a, double[] data, double max, Color c)
        {
            var pts = new PointF[N];
            for (int i = 0; i < N; i++)
            {
                float x = a.Left + (float)a.Width * i / (N - 1);
                float y = a.Bottom - (float)(data[i] / max * a.Height);
                pts[i] = new PointF(x, y);
            }
            var poly = new PointF[N + 2];
            Array.Copy(pts, poly, N);
            poly[N] = new PointF(a.Right, a.Bottom);
            poly[N + 1] = new PointF(a.Left, a.Bottom);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var br = new LinearGradientBrush(new Rectangle(a.Left, a.Top - 1, a.Width, a.Height + 2),
                Theme.Alpha(c, 90), Theme.Alpha(c, 8), LinearGradientMode.Vertical))
                g.FillPolygon(br, poly);
            using (var p = new Pen(c, Math.Max(1.5f, 1.6f * Theme.Scale)) { LineJoin = LineJoin.Round })
                g.DrawLines(p, pts);
        }

        public static GraphicsPath Rounded(Rectangle r, int radius)
        {
            var p = new GraphicsPath();
            int d = radius * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }
}
