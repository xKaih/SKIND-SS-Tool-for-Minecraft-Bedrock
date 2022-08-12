using System;

namespace SKIND_SS_Tool.Utils
{
    internal class getServicesAndProcesses
    {
        //Method that get the PID of a Windows Service
        public static int getPIDOfService(string serviceName)
        {
            int pid = 0;
            string query = "SELECT ProcessId FROM Win32_Service WHERE Name = '" + serviceName + "'";
            System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(query);
            System.Management.ManagementObjectCollection results = searcher.Get();
            foreach (System.Management.ManagementObject result in results)
            {
                pid = Convert.ToInt32(result["ProcessId"]);
            }
            return pid;
        }

        //Method that get the PID of a Windows Process
        public static int getPIDOfProcess(string processName)
        {
            int pid = 0;
            string query = "SELECT ProcessId FROM Win32_Process WHERE Name = '" + processName + "'";
            System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(query);
            System.Management.ManagementObjectCollection results = searcher.Get();
            foreach (System.Management.ManagementObject result in results)
            {
                pid = Convert.ToInt32(result["ProcessId"]);
            }
            return pid;
        }
    }
}
