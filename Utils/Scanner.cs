using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace SKIND_SS_Tool.Utils
{
    internal class Scanner
    {
        public async static Task Initialize()
        {
            initializeDetections();
            //If the system is 64 bits download the string extractor for 64 bits versions, If it isnt download the 32 bits version
            if (Environment.Is64BitOperatingSystem)
            {
                await new WebClient().DownloadFileTaskAsync("https://cdn.discordapp.com/attachments/1228817459838976010/1237451113020788746/strings2.exe?ex=663bb1a8&is=663a6028&hm=532d423ec2c95582d73a4806336a9d2fd2aa885bc43856553aa62111f4af78d3&", "strings.exe");
            }
            else
            {
                await new WebClient().DownloadFileTaskAsync("https://cdn.discordapp.com/attachments/1228817459838976010/1237451113020788746/strings2.exe?ex=663bb1a8&is=663a6028&hm=532d423ec2c95582d73a4806336a9d2fd2aa885bc43856553aa62111f4af78d3&", "strings.exe");
            }
            startRegedit();
            collectStrings();
            File.WriteAllLines("strings.txt", strings.stringsList);
            searchCheats();
            InitializeBypassDetections();
            macroFind();
        }

        //This region contains all of the cheat detection methods 
        #region Strings Detections

        //Download the string from a url and save the strings into a dictionary
        //that their key contains a string and the value the name of the cheat
        private static void initializeDetections()
        {
            WebClient webClient = new WebClient();
            string cheatStrings = webClient.DownloadString("https://rentry.co/skindStrings/raw"); //Update the url (that need to be raw)
            Parallel.ForEach(cheatStrings.Split(new[] {"\r\n"}, StringSplitOptions.None),
                line => //The strings need to be separated by new lines
                {
                    strings.cheatStrings.TryAdd(line.Split('_')[0], line.Split('_')[1]); //Add into the dictionary the string with their cheat name respectively
                });
            Console.WriteLine("Strings loaded: " + strings.cheatStrings.Count);
        }
        //Collect strings of the principal processes
        private static void collectStrings()
        {
            int[] pids = { getServicesAndProcesses.getPIDOfProcess("lsass.exe")
                , getServicesAndProcesses.getPIDOfProcess("ctfmon.exe")
                , getServicesAndProcesses.getPIDOfProcess("regedit.exe")
                , getServicesAndProcesses.getPIDOfService("DPS")
                , getServicesAndProcesses.getPIDOfService("PcaSvc")
            };
            foreach (var VARIABLE in pids)
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "strings.exe",
                        Arguments = $"-nh -raw -pid {VARIABLE}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                while (!proc.StandardOutput.EndOfStream)
                {
                    string line = proc.StandardOutput.ReadLine();
                    strings.stringsList.Add(line.Trim());
                }
            }

        }
        //Start regedit
        private static void startRegedit()
        {
            ProcessStartInfo process = new ProcessStartInfo();
            process.FileName = "regedit.exe";
            process.Verb = "runas";
            process.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(process);
        }
        //Method that search for some strings.cheatStrings key that is in the strings.stringsList string and save in strings.cheatsFounded
        private static void searchCheats()
        {

            Parallel.ForEach(strings.stringsList, new ParallelOptions() { MaxDegreeOfParallelism = (int)Math.Ceiling(((Environment.ProcessorCount * (strings.CPUUsage / 100)))) }, (string line) =>
            {
                foreach (var VARIABLE in strings.cheatStrings)
                {
                    if (line.Contains(VARIABLE.Key))
                    {
                        strings.cheatsFounded.Add(line + "|" + VARIABLE.Value);
                    }
                }
            });

            Console.WriteLine("Cheats founded with string scanner: " + strings.cheatsFounded.Count);
        }

        #endregion

        //This region contains all of the bypass methods detection
        #region Bypass Methods
        //Run all bypass methods
        private static void InitializeBypassDetections()
        {
            prefetchDisabled();
            regeditDisabled();
            veracrypt();
            stoppedServices();
            taskManagerDisabled();
            regeditDisallowRun();

            //Print number of bypass methods founded
            Console.WriteLine("Bypass methods founded: " + strings.bypassMethods.Count);
        }

        //Detect if prefetch is disabled or not for Win10
        private static void prefetchDisabled()
        {
            if ((int)Registry.GetValue(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                    "EnableSuperfetch", 1) == 0 && Environment.OSVersion.Version.Major == 10)
            {
                strings.bypassMethods.Add("The prefetch is off!!!");
            }
        }

        //Detect if some app is disable with regedit
        private static void regeditDisabled()
        {
            if ((string)Registry.GetValue(
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                    "nolog",
                    "") != "" && Registry.GetValue(
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                    "nolog",
                    "") != null)
            {
                strings.bypassMethods.Add("Some app is disabled, check HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist!!!");

            }
        }

        //Detect mounted devices on Veracrytp
        private static void veracrypt()
        {
            var deletedPartitions =
                Registry.LocalMachine.OpenSubKey("SYSTEM\\MountedDevices");
            List<string> posibleDeletedPartitionsValues = new List<string>();

            for (int i = 0; i < deletedPartitions.GetValueNames().Length; i++)
            {
                if (deletedPartitions.GetValueNames()[i].Contains("??"))
                {
                    var element = (byte[])deletedPartitions.GetValue(deletedPartitions.GetValueNames()[i]);
                    posibleDeletedPartitionsValues.Add(BitConverter.ToString(element).Replace("-", " "));
                }
            }


            foreach (var VARIABLE in posibleDeletedPartitionsValues)
            {
                if (VARIABLE.Contains("56 00 65 00 72 00 61 00 63 00 72 00 79 00 70 00 74"))
                    strings.bypassMethods.Add(
                        "A partition was be deleted with Veracrypt, check the registry key SYSTEM\\MountedDevices!!!");
            }
        }

        //Detect Paused DPS, PCASVC, AppInfo and EventLog services
        private static void stoppedServices()
        {
            ServiceController sc = new ServiceController("DPS");
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                strings.bypassMethods.Add("The DPS service is stopped!!!");
            }
            sc = new ServiceController("PcaSvc");
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                strings.bypassMethods.Add("The PcaSvc service is stopped!!!");
            }
            sc = new ServiceController("AppInfo");
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                strings.bypassMethods.Add("The AppInfo service is stopped!!!");
            }
            sc = new ServiceController("EventLog");
            if (sc.Status == ServiceControllerStatus.Stopped)
            {
                strings.bypassMethods.Add("The EventLog service is stopped!!!");
            }

        }

        //Detect if taskmanager is disable with regedit
        private static void taskManagerDisabled()
        {
            try
            {
                int task = int.Parse(Registry.GetValue(
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "DisableTaskMgr", 0).ToString());
                if (task == 1)
                    strings.bypassMethods.Add("The taskmanager is disabled, check the registry key HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System!!!");
            }
            catch (Exception e) { }

        }

        //Detect if some app is disable with regedit and DisallowRun
        private static void regeditDisallowRun()
        {
            var key = Registry.CurrentUser.OpenSubKey(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\explorer\\DisallowRun");
            if (key != null)
            {
                string[] names = key.GetValueNames();
                foreach (var VARIABLE in names)
                {
                    if (key.GetValue(VARIABLE).ToString().Contains(".exe"))
                        strings.bypassMethods.Add(
                            "Some app is disabled, check HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer!!!");
                }
            }
        }

        //Detect if wmic was used (On the next update)

        #endregion

        //Search Macros
        public static void macroFind()
        {
            string specialFolder;
            DateTime lastWriteTime;
            if (File.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\Local\\LGHUB\\settings.db"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData\\Local";
                lastWriteTime = File.GetLastAccessTime(specialFolder + "\\LGHUB\\settings.db");
                strings.macroDetect.Add(string.Concat("Logitech mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (Directory.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\BYCOMBO-2\\mac"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime = Directory.GetLastWriteTime(specialFolder + "\\BYCOMBO-2\\mac");
                strings.macroDetect.Add(string.Concat("Glorious mouse detected , Config folder Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists($"C:\\ProgramData\\Razer\\Synapse3\\Log\\Synapse\\SynapseService.log"))
            {
                string text = File.ReadAllText("C:\\ProgramData\\Razer\\Synapse3\\Log\\Synapse\\SynapseService.log");
                strings.macroDetect.Add(text.Contains("Turbo: True") ? "Razer macro has been detected, ban the user" : "");
            }

            if (File.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\corsair\\CUE\\config.cuecfg"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\corsair\\CUE\\config.cuecfg");
                strings.macroDetect.Add(string.Concat("Corsair (CUE) mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\corsair\\CUE4\\config.cuecfg"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\corsair\\CUE4\\config.cuecfg");
                strings.macroDetect.Add(string.Concat("Corsair (CUE4) mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (Directory.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\corsair\\CUE4\\Profiles"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    Directory.GetLastWriteTime(specialFolder + "\\corsair\\CUE4\\Profiles");
                strings.macroDetect.Add(string.Concat("Corsair (CUE4) mouse detected , Config folder Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (Directory.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\corsair\\CUE\\Profiles"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    Directory.GetLastWriteTime(specialFolder + "\\corsair\\CUE\\Profiles");
                strings.macroDetect.Add(string.Concat("Corsair (CUE) mouse detected , Config folder Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists("C:\\Program Files (x86)\\Bloody7\\Bloody7\\UserLog\\Mouse\\TLcir_9EFF3FF4\\language\\Settings\\EnvironmentVar.ini"))
            {
                specialFolder = "C:\\Program Files (x86)";
                lastWriteTime = File.GetLastWriteTime(specialFolder +
                    "\\Bloody7\\Bloody7\\UserLog\\Mouse\\TLcir_9EFF3FF4\\language\\Settings\\EnvironmentVar.ini");
                strings.macroDetect.Add(string.Concat("Bloody mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\steelseries-engine-3-client\\Session Storage\\000003.log"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime = File.GetLastWriteTime(specialFolder +
                    "\\steelseries-engine-3-client\\Session Storage\\000003.log");
                strings.macroDetect.Add(string.Concat("Steelseries mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists("C:\\Program Files\\Gaming MouseV30\\record.ini"))
            {
                specialFolder = "C:\\Program Files";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\Gaming MouseV30\\record.ini");
                strings.macroDetect.Add(string.Concat("Motospeed mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists("C:\\Program Files (x86)\\Gaming Mouse\\Config.ini"))
            {
                specialFolder = "C:\\Program Files (x86)";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\Gaming Mouse\\Config.ini");
                strings.macroDetect.Add(string.Concat("Marsgaming mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists($"C:\\Users\\{Environment.UserName}\\AppData\\Local\\BY-8801-GM917-v108\\curid.dtc"))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData\\Local";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\BY-8801-GM917-v108\\curid.dtc");
                strings.macroDetect.Add(string.Concat("Marsgaming mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists("C:\\Program Files\\AYAX GamingMouse\\config.bin"))
            {
                specialFolder = "C:\\Program Files";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\AYAX GamingMouse\\config.bin");
                strings.macroDetect.Add(string.Concat("Ayax mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists(
                    string.Concat($"C:\\Users\\{Environment.UserName}\\AppData\\Local\\BY-COMBO\\pro.dtc")))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData\\Local";
                lastWriteTime = File.GetLastWriteTime(specialFolder + "\\BY-COMBO\\pro.dtc");
                strings.macroDetect.Add(string.Concat("T16 mouse detected , Config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (Directory.Exists(
                    string.Concat("C:\\Program Files (x86)\\Xenon200\\Configs")))
            {
                specialFolder = "C:\\Program Files (x86)";
                lastWriteTime = Directory.GetLastWriteTime(specialFolder + "\\Xenon200\\Configs");
                strings.macroDetect.Add(string.Concat("Xenon200 mouse detected , Config folder Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (File.Exists(string.Concat($"C:\\Users\\{Environment.UserName}\\AppData\\REDRAGON\\GamingMouse\\config.ini")))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\REDRAGON\\GamingMouse\\config.ini");
                strings.macroDetect.Add(string.Concat("Redragon mouse detected , First config file Modified at: ",
                    lastWriteTime.ToString()));
            }

            if (File.Exists(string.Concat($"C:\\Users\\{Environment.UserName}\\AppData\\REDRAGON\\GamingMouse\\macro.ini")))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    File.GetLastWriteTime(specialFolder + "\\REDRAGON\\GamingMouse\\macro.ini");
                strings.macroDetect.Add(string.Concat("                          Second config file Modified at: ",
                    lastWriteTime.ToString()));
            }

            if (Directory.Exists(string.Concat($"C:\\Users\\{Environment.UserName}\\AppData\\REDRAGON\\GamingMouse\\Macro")))
            {
                specialFolder = $"C:\\Users\\{Environment.UserName}\\AppData";
                lastWriteTime =
                    Directory.GetLastWriteTime(specialFolder + "\\REDRAGON\\GamingMouse\\Macro");
                strings.macroDetect.Add(string.Concat("                          Folder config file Modified at: ",
                    lastWriteTime.ToString()));

            }

            if (Directory.Exists("C:\\Blackweb Gaming AP\\config"))
            {
                FileInfo[] files = (new DirectoryInfo("C:\\Blackweb Gaming AP\\config")).GetFiles("*.MA32AIY");
                for (int i = 0; i < (int)files.Length; i++)
                {
                    FileInfo fileInfo = files[i];
                    if ((DateTime.Now - fileInfo.LastWriteTime).Hours >= 1)
                    {
                        strings.macroDetect.Add("Blackweb mouse detected, Config file was recently modified");

                    }
                }
            }
        }
    }
}
