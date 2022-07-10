using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using WUApiLib;

namespace Windows_Handler
{
    public class Windows
    {
        public static void Defender(bool enable)
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;
            if (!enable)
            {
                Methods.CheckDefender(false);
                Methods.EditRegistry(@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "1");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "1");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "1");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", "1");
            }
            if (enable)
            {
                Methods.CheckDefender(true);
                Methods.EditRegistry(@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "1");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "0");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "0");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "0");
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", "0");
            }
        }
        public static void Updates(bool enable)
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;

            if (!enable)
            {
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "1");
            }
            if (enable)
            {
                Methods.EditRegistry(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "0");
            }
        }
        public static void UAC(bool enable)
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;

            if (!enable)
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0");
            }
            if (enable)
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "1");
            }
        }
        public static bool IsSecureBootEnabled()
        {
            var value = (int?)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "EnableLUA", null);
            if (value.HasValue)
                return true;

            return false;
        }
        public static string GetDirectXVersion()
        {
            int directxMajorVersion = 0;
            var OSVersion = Environment.OSVersion;
            if (OSVersion.Version.Major >= 6)
            {
                if (OSVersion.Version.Major > 6 || OSVersion.Version.Minor >= 1)
                {
                    directxMajorVersion = 11;
                }
                else
                {
                    directxMajorVersion = 10;
                }
            }
            else
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\DirectX"))
                {
                    string versionStr = key.GetValue("Version") as string;
                    if (!string.IsNullOrEmpty(versionStr))
                    {
                        var versionComponents = versionStr.Split('.');
                        if (versionComponents.Length > 1)
                        {
                            int directXLevel;
                            if (int.TryParse(versionComponents[1], out directXLevel))
                            {
                                directxMajorVersion = directXLevel;
                            }
                        }
                    }
                }
            }
            return "DirectX Version: " + directxMajorVersion.ToString();
        }
        public static bool IsRedist64Installed()
        {
            string keyName = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{3746f21b-c990-4045-bb33-1cf98cff7a68}";
            string valueName = "DisplayName";
            if (Registry.GetValue(keyName, valueName, null) == null)
                return false;

            return true;
        }
        public static bool IsRedist86Installed()
        {
            string keyName = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{a98dc6ff-d360-4878-9f0a-915eba86eaf3}";
            string valueName = "DisplayName";
            if (Registry.GetValue(keyName, valueName, null) == null)
                return false;

            return true;
        }
        public static bool IsUACEnabled()
        {
            var cmd = Methods.RunCMD(@"(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA");
            while (!cmd.StandardOutput.EndOfStream)
            {
                string line = cmd.StandardOutput.ReadLine();
                if (line.Contains("0"))
                    return false;
            }
            return true;
        }
        public static List<string> HotFixes()
        {
            List<string> list = new List<string>();

            var updateSession = new UpdateSession();
            var updateSearcher = updateSession.CreateUpdateSearcher();
            var count = updateSearcher.GetTotalHistoryCount();
            var history = updateSearcher.QueryHistory(0, count);

            for (int i = 0; i < count; ++i)
                list.Add(history[i].Title.ToString());

            return list;
        }
        public static List<string> StartupPrograms(bool remove = false)
        {
            List<string> list = new List<string>();
            RegistryKey currUser = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            RegistryKey localMachine32 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            RegistryKey localMachine64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            localMachine64 = localMachine64.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

            foreach (string value in currUser.GetValueNames())
            {
                list.Add(value);
                if (remove)
                {
                    currUser.DeleteValue(value);
                }
            }
            currUser.Close();

            foreach (string value in localMachine32.GetValueNames())
            {
                list.Add(value);
                if (remove)
                {
                    localMachine32.DeleteValue(value);
                }
            }
            localMachine32.Close();

            foreach (string value in localMachine64.GetValueNames())
            {
                list.Add(value);
                if (remove)
                {
                    localMachine64.DeleteValue(value);
                }
                localMachine64.Close();
            }
            return list;
        }
        public static string OperatingSystem()
        {
            RegistryKey osSubKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string os = osSubKey.GetValue("ProductName").ToString();
            return os;
        }
        public static string GPU()
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "(Get-WmiObject Win32_VideoController).Name",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                string line = proc.StandardOutput.ReadLine();
                return line;
            }
            return null;
        }
        public static string RAM(string type = "")
        {
            ManagementScope Scope;
            Scope = new ManagementScope(String.Format("\\\\{0}\\root\\CIMV2", "."), null);

            Scope.Connect();
            ObjectQuery Query = new ObjectQuery("SELECT Capacity FROM Win32_PhysicalMemory");
            ManagementObjectSearcher Searcher = new ManagementObjectSearcher(Scope, Query);
            UInt64 capacity = 0;
            foreach (ManagementObject WmiObject in Searcher.Get())
            {
                capacity += (UInt64)WmiObject["Capacity"];
            }
            if (type == "gb")
            {
                string GB = String.Format("{0}GB", capacity / (1024 * 1024 * 1024));
                return GB;
            }
            if (type == "mb")
            {
                string MB = String.Format("{0}MB", capacity / (1024 * 1024));
                return MB;
            }
            string kb = String.Format("{0}KB", capacity);
            return kb;
        }
        public static string SystemRoot()
        {
            RegistryKey osSubKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string root = osSubKey.GetValue("SystemRoot").ToString();
            return root;
        }
        public static string OperatingSystemVersion()
        {
            RegistryKey osSubKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string version = osSubKey.GetValue("DisplayVersion").ToString();
            return version;
        }
        public static string ProcessorName()
        {
            RegistryKey processorSubKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            string processor = processorSubKey.GetValue("ProcessorNameString").ToString();
            return processor;
        }
        public static string BiosManufactrer()
        {
            RegistryKey biosManufactrerKeyName = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            string bios = biosManufactrerKeyName.GetValue("BaseBoardManufacturer").ToString();
            return bios;
        }
        public static string BiosName()
        {
            RegistryKey biosProductKeyName = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            string bios = biosProductKeyName.GetValue("SystemProductName").ToString();
            return bios;
        }
        public static bool Virtualization()
        {
            var cmd = Methods.RunPS("Get-CimInstance -ClassName win32_processor -Property VirtualizationFirmwareEnabled | Format-List VirtualizationFirmwareEnabled");
            while (cmd.StandardOutput.EndOfStream)
            {
                string virt = cmd.StandardOutput.ReadLine();
                if (virt.EndsWith("False"))
                    return false;
            }
            return true;
        }
        public static bool HyperV()
        {
            var cmd = Methods.RunPS("Get-ComputerInfo -property \"HyperV*\" | Format-List HyperVRequirementVirtualizationFirmwareEnabled");
            while (cmd.StandardOutput.EndOfStream)
            {
                string virt = cmd.StandardOutput.ReadLine();
                if (virt.EndsWith("False"))
                    return false;
            }
            return true;
        }
        public static string BootMode()
        {
            var cmd = Methods.RunCMD("$env:firmware_type");
            while (!cmd.StandardOutput.EndOfStream)
            {
                string line = cmd.StandardOutput.ReadLine();

                if (line.Contains("Legacy"))
                    return "Legacy";
            }
            return "UEFI";
        }
        public static string DiskPartition()
        {
            var cmd = Methods.RunCMD("Get-Disk");
            while (!cmd.StandardOutput.EndOfStream)
            {
                string line = cmd.StandardOutput.ReadLine();

                if (line.Contains("MBR"))
                    return "MBR";
            }
            return "GPT";
        }
        public static void ClearFolder(string path)
        {
            DirectoryInfo dir = new DirectoryInfo(path);

            foreach (FileInfo fi in dir.GetFiles())
            {
                try
                {
                    fi.Delete();
                }
                catch { }
            }

            foreach (DirectoryInfo di in dir.GetDirectories())
            {
                ClearFolder(di.FullName);
                try
                {
                    di.Delete();
                }
                catch { }
            }
        }
        public bool RunExe(byte[] data, bool runSilentInstallation = false)
        {
            new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;
                if (data == null)
                    throw new ArgumentNullException("Exe data cannot be null");
                try
                {

                    string tempExeName = Path.Combine(Directory.GetCurrentDirectory(), "temp.exe");
                    if (File.Exists(tempExeName))
                        File.Delete(tempExeName);

                    using (FileStream fsDst = new FileStream(tempExeName, FileMode.CreateNew, FileAccess.Write))
                    {
                        fsDst.Write(data, 0, data.Length);
                    }
                    File.SetAttributes(tempExeName, FileAttributes.Hidden);

                    var proc = new Process();
                    proc.StartInfo.FileName = tempExeName;

                    if (runSilentInstallation)
                        proc.StartInfo.Arguments = "/quiet";

                    proc.Start();
                    proc.WaitForExit();
                    File.Delete(tempExeName);
                    File.Delete("temp.exe");
                    File.Delete("temp.ini");
                }
                catch { }

            }).Start();
            return true;
        }
        public static string EFT(bool gameLocation = false)
        {
            if (gameLocation)
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EscapeFromTarkov"))
                {
                    if (key != null)
                    {
                        Object o = key.GetValue("InstallLocation");
                        if (o != null)
                            return o.ToString();
                    }
                    return "Unable to get launcher install location";
                }
            }
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B0FDA062-7581-4D67-B085-C4E7C358037F}_is1"))
            {
                if (key != null)
                {
                    Object o = key.GetValue("InstallLocation");
                    if (o != null)
                        return o.ToString();
                }
                return "Unable to get launcher install location";
            }
        }
        public static bool IsProcessRunning(string processName)
        {
            Process[] process = Process.GetProcessesByName(processName);
            if (process.Length == 0)
                return false;

            return true;
        }
        public static bool IsAntiVirusInstalled()
        {
            string scope = "\\\\" + Environment.MachineName + "\\root\\SecurityCenter";
            if (new ManagementObjectSearcher(scope, "SELECT * FROM AntivirusProduct").Get().Count > 0)
                return true;

            return false;
        }
        public static bool IsServiceRunning(string serviceName)
        {
            if (new ServiceController(serviceName).Status == ServiceControllerStatus.Running)
                return true;

            return false;
            //vgk
            //faceit
            //esea
            //easyanticheat
            //battleye
        }
        public static List<string> GetServices()
        {
            ServiceController[] services = ServiceController.GetServices();
            List<string> list = new List<string>();

            foreach (ServiceController service in services)
            {
                string item = service.DisplayName + " - " + service.Status;
                list.Add(item);
            }
            return list;
        }
        public static List<string> GetRunningProcesses()
        {
            List<string> list = new List<string>();
            Process[] processes = Process.GetProcesses();

            foreach (Process proc in processes)
            {
                list.Add(proc.ProcessName);
            }
            return list;
        }
    }
}