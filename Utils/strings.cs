using System.Collections.Concurrent;
using System.Collections.Generic;

namespace SKIND_SS_Tool.Utils
{
    static class strings
    {
        public static ConcurrentDictionary<string, string> cheatStrings = new ConcurrentDictionary<string, string>();
        public static ConcurrentBag<string> cheatsFounded = new ConcurrentBag<string>();
        public static ConcurrentBag<string> stringsList = new ConcurrentBag<string>();
        public static ConcurrentBag<string> bypassMethods = new ConcurrentBag<string>();
        public static ConcurrentBag<string> macroDetect = new ConcurrentBag<string>();
        public static double CPUUsage = 0;
    }
}
