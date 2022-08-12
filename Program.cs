using System;
using System.Windows.Forms;

namespace SKIND_SS_Tool
{
    internal static class Program
    {
        /// <summary>
        /// Punto de entrada principal para la aplicación.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Console.Title = "SKIND";
            Console.WriteLine("Console Log:"); //Dont pay attention to this, its for the devs.
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());

        }
    }
}
