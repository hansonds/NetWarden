using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("NetWarden")]
[assembly: AssemblyProduct("NetWarden")]
[assembly: AssemblyDescription("Per-application bandwidth monitor, limiter and blocker")]
[assembly: AssemblyCopyright("Hanson")]
[assembly: AssemblyVersion("1.1.0.0")]
[assembly: AssemblyFileVersion("1.1.0.0")]
[assembly: AssemblyInformationalVersion("1.1.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: ComVisible(false)]

namespace NetWarden
{
    internal static class Program
    {
        public const string Version = "1.1.0";

        [STAThread]
        static void Main(string[] args)
        {
            bool created;
            using (var mutex = new Mutex(true, @"Local\NetWarden_SingleInstance_7f3a", out created))
            using (var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\NetWarden_Show_7f3a"))
            {
                if (!created) { showEvent.Set(); return; }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) => Crash(e.Exception);
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Crash(e.ExceptionObject as Exception);

                if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
                {
                    MessageBox.Show("NetWarden needs Administrator rights to monitor and control network traffic.\n\nRight-click NetWarden.exe → Run as administrator.",
                        "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (!Environment.Is64BitOperatingSystem || !Environment.Is64BitProcess)
                {
                    MessageBox.Show("NetWarden requires 64-bit Windows.", "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                string err;
                if (!PrepareDriver(out err))
                {
                    MessageBox.Show("Could not prepare the network driver:\n\n" + err, "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                var engine = new TrafficEngine();
                if (!engine.Start(out err))
                {
                    MessageBox.Show("Could not start network monitoring:\n\n" + err, "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                bool minimized = Array.Exists(args, a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));
                var cfg = Config.Load();
                try
                {
                    Application.Run(new MainForm(engine, cfg, minimized, showEvent));
                }
                finally
                {
                    engine.Dispose();
                    cfg.Save();
                }
                GC.KeepAlive(mutex);
            }
        }

        /// <summary>WinDivert.dll + WinDivert64.sys are embedded in the EXE and unpacked next to it on first run
        /// (or to ProgramData if the EXE's folder isn't writable).</summary>
        static bool PrepareDriver(out string error)
        {
            error = null;
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string dir = null;
            if (File.Exists(Path.Combine(exeDir, "WinDivert.dll")) && File.Exists(Path.Combine(exeDir, "WinDivert64.sys")))
                dir = exeDir;
            else
            {
                dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetWarden", "driver");
                try
                {
                    Directory.CreateDirectory(dir);
                    Extract("WinDivert.dll", dir);
                    Extract("WinDivert64.sys", dir);
                }
                catch (Exception ex) { error = ex.Message; return false; }
            }
            if (Win32.LoadLibrary(Path.Combine(dir, "WinDivert.dll")) == IntPtr.Zero)
            {
                error = "LoadLibrary failed (error " + Marshal.GetLastWin32Error() + ").";
                return false;
            }
            return true;
        }

        static void Extract(string name, string dir)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetWarden." + name))
            {
                if (s == null) throw new Exception("Embedded " + name + " missing.");
                string target = Path.Combine(dir, name);
                if (File.Exists(target) && new FileInfo(target).Length == s.Length) return;
                try { using (var f = File.Create(target)) s.CopyTo(f); }
                catch (IOException) { if (!File.Exists(target)) throw; } // in use by a loaded driver: keep it
            }
        }

        static void Crash(Exception ex)
        {
            if (ex == null) return;
            try
            {
                Directory.CreateDirectory(Config.Dir);
                File.AppendAllText(Path.Combine(Config.Dir, "error.log"), DateTime.Now + "\r\n" + ex + "\r\n\r\n");
            }
            catch { }
            MessageBox.Show("Something went wrong:\n\n" + ex.Message + "\n\nDetails were saved to %AppData%\\NetWarden\\error.log",
                "NetWarden", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
