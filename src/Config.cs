using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace NetWarden
{
    [DataContract]
    internal sealed class Rule
    {
        [DataMember] public string Key;        // lowercase exe path
        [DataMember] public string Path;
        [DataMember] public string Name;
        [DataMember] public long DownLimit;    // bytes per second, 0 = unlimited
        [DataMember] public long UpLimit;
        [DataMember] public bool Block;
        [DataMember] public bool Disabled;
        [DataMember] public string DownUnit;   // display unit, e.g. "KB/s" (null = KB/s)
        [DataMember] public string UpUnit;
    }

    [DataContract]
    internal sealed class Config
    {
        [DataMember] public List<Rule> Rules = new List<Rule>();
        [DataMember] public long GlobalDown;
        [DataMember] public long GlobalUp;
        [DataMember] public string GlobalDownUnit;
        [DataMember] public string GlobalUpUnit;
        [DataMember] public bool RulesPaused;
        [DataMember] public bool ExitOnClose;      // false = close button hides to tray
        [DataMember] public bool ShowIdle;
        [DataMember] public int SortColumn = 1;
        [DataMember] public bool SortAsc;

        public static string Dir
        {
            get { return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetWarden"); }
        }
        static string FilePath { get { return System.IO.Path.Combine(Dir, "config.json"); } }

        public Rule Find(string key)
        {
            foreach (var r in Rules) if (r.Key == key) return r;
            return null;
        }

        public static Config Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    using (var fs = File.OpenRead(FilePath))
                    {
                        var c = (Config)new DataContractJsonSerializer(typeof(Config)).ReadObject(fs);
                        if (c.Rules == null) c.Rules = new List<Rule>();
                        c.Rules.RemoveAll(r => r == null || r.Key == null);
                        return c;
                    }
                }
            }
            catch { }
            return new Config();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                string tmp = FilePath + ".tmp";
                using (var fs = File.Create(tmp))
                    new DataContractJsonSerializer(typeof(Config)).WriteObject(fs, this);
                if (File.Exists(FilePath)) File.Delete(FilePath);
                File.Move(tmp, FilePath);
            }
            catch { }
        }
    }

    /// <summary>"Start with Windows" via an elevated logon task (a Run-key entry can't start an admin app silently).</summary>
    internal static class AutoStart
    {
        const string TaskName = "NetWarden";

        static int Schtasks(string args)
        {
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                p.WaitForExit(10000);
                return p.ExitCode;
            }
        }

        public static bool IsEnabled()
        {
            try { return Schtasks("/Query /TN \"" + TaskName + "\"") == 0; } catch { return false; }
        }

        public static bool Set(bool enable)
        {
            try
            {
                if (!enable) return Schtasks("/Delete /TN \"" + TaskName + "\" /F") == 0;

                string exe = Process.GetCurrentProcess().MainModule.FileName;
                string user = WindowsIdentity.GetCurrent().Name;
                string xml =
"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
"  <RegistrationInfo><Description>Starts NetWarden (bandwidth monitor) at logon.</Description></RegistrationInfo>\r\n" +
"  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + SecurityElement.Escape(user) + "</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>\r\n" +
"  <Principals><Principal id=\"Author\"><UserId>" + SecurityElement.Escape(user) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n" +
"  <Settings>\r\n" +
"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
"    <AllowHardTerminate>true</AllowHardTerminate>\r\n" +
"    <StartWhenAvailable>false</StartWhenAvailable>\r\n" +
"    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n" +
"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n" +
"    <Priority>5</Priority>\r\n" +
"  </Settings>\r\n" +
"  <Actions Context=\"Author\"><Exec><Command>" + SecurityElement.Escape(exe) + "</Command><Arguments>--minimized</Arguments></Exec></Actions>\r\n" +
"</Task>\r\n";
                string tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "netwarden_task.xml");
                File.WriteAllText(tmp, xml, Encoding.Unicode);
                int rc = Schtasks("/Create /TN \"" + TaskName + "\" /XML \"" + tmp + "\" /F");
                try { File.Delete(tmp); } catch { }
                return rc == 0;
            }
            catch { return false; }
        }
    }
}
