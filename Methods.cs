using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace Windows_Handler
{
    public class Methods
    {
        public static void EditRegistry(string regPath, string name, string value)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    if (key == null)
                    {
                        Registry.LocalMachine.CreateSubKey(regPath).SetValue(name, value, RegistryValueKind.DWord);
                        return;
                    }
                    if (key.GetValue(name) != (object)value)
                        key.SetValue(name, value, RegistryValueKind.DWord);
                }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.ToString());
            }
        }
        public static void CheckDefender(bool enable)
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "Get-MpPreference -verbose",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            };

            if (!enable)
            {
                proc.Start();
                while (!proc.StandardOutput.EndOfStream)
                {
                    string line = proc.StandardOutput.ReadLine();
                    if (line.StartsWith(@"DisableRealtimeMonitoring") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableRealtimeMonitoring $True"); //real-time protection

                    else if (line.StartsWith(@"DisableBehaviorMonitoring") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableBehaviorMonitoring $True"); //behavior monitoring

                    else if (line.StartsWith(@"DisableBlockAtFirstSeen") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableBlockAtFirstSeen $True");

                    else if (line.StartsWith(@"DisableIOAVProtection") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableIOAVProtection $True"); //scans all downloaded files and attachments

                    else if (line.StartsWith(@"DisablePrivacyMode") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisablePrivacyMode $True"); //displaying threat history

                    else if (line.StartsWith(@"SignatureDisableUpdateOnStartupWithoutEngine") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $True"); //definition updates on startup

                    else if (line.StartsWith(@"DisableArchiveScanning") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableArchiveScanning $True"); //scan archive files, such as .zip and .cab files

                    else if (line.StartsWith(@"DisableIntrusionPreventionSystem") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableIntrusionPreventionSystem $True"); // network protection 

                    else if (line.StartsWith(@"DisableScriptScanning") && line.EndsWith("False"))
                        RunPS("Set-MpPreference -DisableScriptScanning $True"); //scanning of scripts during scans

                    else if (line.StartsWith(@"SubmitSamplesConsent") && !line.EndsWith("2"))
                        RunPS("Set-MpPreference -SubmitSamplesConsent 2"); //MAPSReporting 

                    else if (line.StartsWith(@"MAPSReporting") && !line.EndsWith("0"))
                        RunPS("Set-MpPreference -MAPSReporting 0"); //MAPSReporting 

                    else if (line.StartsWith(@"HighThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -HighThreatDefaultAction 6 -Force"); // high level threat // Allow

                    else if (line.StartsWith(@"ModerateThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -ModerateThreatDefaultAction 6"); // moderate level threat

                    else if (line.StartsWith(@"LowThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -LowThreatDefaultAction 6"); // low level threat

                    else if (line.StartsWith(@"SevereThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -SevereThreatDefaultAction 6"); // severe level threat
                }
            }
            if (enable)
            {
                proc.Start();
                while (!proc.StandardOutput.EndOfStream)
                {
                    string line = proc.StandardOutput.ReadLine();
                    if (line.StartsWith(@"DisableRealtimeMonitoring") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableRealtimeMonitoring $False"); //real-time protection

                    else if (line.StartsWith(@"DisableBehaviorMonitoring") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableBehaviorMonitoring $False"); //behavior monitoring

                    else if (line.StartsWith(@"DisableBlockAtFirstSeen") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableBlockAtFirstSeen $False");

                    else if (line.StartsWith(@"DisableIOAVProtection") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableIOAVProtection $False"); //scans all downloaded files and attachments

                    else if (line.StartsWith(@"DisablePrivacyMode") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisablePrivacyMode $False"); //displaying threat history

                    else if (line.StartsWith(@"SignatureDisableUpdateOnStartupWithoutEngine") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $False"); //definition updates on startup

                    else if (line.StartsWith(@"DisableArchiveScanning") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableArchiveScanning $False"); //scan archive files, such as .zip and .cab files

                    else if (line.StartsWith(@"DisableIntrusionPreventionSystem") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableIntrusionPreventionSystem $False"); // network protection 

                    else if (line.StartsWith(@"DisableScriptScanning") && line.EndsWith("True"))
                        RunPS("Set-MpPreference -DisableScriptScanning $False"); //scanning of scripts during scans

                    else if (line.StartsWith(@"SubmitSamplesConsent") && !line.EndsWith("2"))
                        RunPS("Set-MpPreference -SubmitSamplesConsent 1"); //MAPSReporting 

                    else if (line.StartsWith(@"MAPSReporting") && !line.EndsWith("0"))
                        RunPS("Set-MpPreference -MAPSReporting 2"); //MAPSReporting 

                    else if (line.StartsWith(@"HighThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -HighThreatDefaultAction 0 -Force"); // high level threat // Allow

                    else if (line.StartsWith(@"ModerateThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -ModerateThreatDefaultAction 0"); // moderate level threat

                    else if (line.StartsWith(@"LowThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -LowThreatDefaultAction 0"); // low level threat

                    else if (line.StartsWith(@"SevereThreatDefaultAction") && !line.EndsWith("6"))
                        RunPS("Set-MpPreference -SevereThreatDefaultAction 0"); // severe level threat
                }
            }

        }
        public static Process RunPS(string args)
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                }

            };
            proc.Start();
            return proc;
        }
        public static Process RunCMD(string args)
        {
            ProcessStartInfo PowerShellInfo = new ProcessStartInfo();
            PowerShellInfo.FileName = "powershell.exe";
            PowerShellInfo.Arguments = args;
            PowerShellInfo.CreateNoWindow = true;
            PowerShellInfo.UseShellExecute = false;
            PowerShellInfo.RedirectStandardOutput = true;

            Process PowerShell = new Process();
            PowerShell.StartInfo = PowerShellInfo;
            PowerShell.Start();
            return PowerShell;
        }
    }
}


