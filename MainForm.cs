using SKIND_SS_Tool.Utils;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SKIND_SS_Tool
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void pictureBox1_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            //Load Fonts
            try
            {
                loadFonts loadFonts = new loadFonts();
                loadFonts.loadFontOnMemory(Properties.Resources.GREENHOUSEGAS);
                loadFonts.loadFontOnMemory(Properties.Resources.Beacon);
                loadFonts.loadFontsIntoControl(new Control[] { label1, fileScan, label3 }, 1);
                loadFonts.loadFontsIntoControl(new Control[] { ScanDevice }, 0);
            }
            catch (Exception exception)
            {
                Console.WriteLine("ERROR LOADING THE FONTS:\r\n" + exception);
                Console.ReadLine();
                throw;
            }

            //Load scan file status
            wait.BringToFront();

            //Disable Scan Button
            ScanDevice.Enabled = false;
        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {
            scanFileTask().GetAwaiter().GetResult();
        }

        //Method that return a bool if a byte array contains other byte array
        public static bool Contains(byte[] array, byte[] arrayToSearch)
        {
            if (arrayToSearch.Length > array.Length)
                return false;
            for (int i = 0; i < array.Length - arrayToSearch.Length + 1; i++)
            {
                bool found = true;
                for (int j = 0; j < arrayToSearch.Length; j++)
                {
                    if (array[i + j] != arrayToSearch[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return true;
            }
            return false;
        }

        private void guna2TextBox1_TextChanged(object sender, EventArgs e)
        {
            //If the textbox is empty, the button will be disabled
            if (string.IsNullOrEmpty(CPUUsage.Text))
            {
                ScanDevice.Enabled = false;
            }
            else
            {
                ScanDevice.Enabled = true;
            }
            //If the textbox not contains only numbers, the button will be disabled
            if (!CPUUsage.Text.All(char.IsDigit))
            {
                ScanDevice.Enabled = false;
            }
            else
            {
                ScanDevice.Enabled = true;
            }
            //If the textbox number is upper than 100, the button will be disabled
            if (Convert.ToInt32(CPUUsage.Text) > 100)
            {
                ScanDevice.Enabled = false;
            }
            else
            {
                ScanDevice.Enabled = true;
            }
        }

        #region Scan

        private async void ScanDevice_Click(object sender, EventArgs e)
        {
            ScanDevice.Text = "Scanning...";
            ScanDevice.Enabled = false;
            strings.CPUUsage = double.Parse(CPUUsage.Text);
            await Task.Run(Scanner.Initialize);
            ScanDevice.Text = "Finished";
            ScanDevice.Enabled = true;
            if(strings.bypassMethods.Count > 0)
                File.WriteAllLines("bypass.txt",strings.bypassMethods);
            else
            {
                File.WriteAllText("bypass.txt", "Nothing Founded");
            }
            for (int i = 0; i < strings.cheatsFounded.Count; i++)
            { 
                results.Rows.Add(new object[] { strings.cheatsFounded[i].Split(new[] { "|" }, StringSplitOptions.None)[0], strings.cheatsFounded[i].Split(new[] { "|" }, StringSplitOptions.None)[1]});
            }

            results.Rows.Add(new object[] { "Nothing Founded", "Nothing Founded" });
            
        }
        private async Task scanFileTask()
        {
            if (DialogResult.OK == scanFile.ShowDialog())
            {
                if (scanFile.FileName.EndsWith(".exe"))
                {
                    wait.BringToFront();
                    //This is so raw/simple so can have a lot of falses positives
                    if (File.ReadAllText(scanFile.FileName).Contains("WriteProcessMemory"))

                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("THE FILE PROBABLY IS A CHEAT (THIS CAN THROW FALSES POSITIVES)!!");
                        Console.ResetColor();
                        cheat.BringToFront();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("THE FILE PROBABLY IS NOT A CHEAT (THIS CAN THROW FALSES POSITIVES)!!");
                        Console.ResetColor();
                        clean.BringToFront();
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("Error getting the file of File Scan section, try again");
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("Error getting the file of File Scan section, try again");
                Console.ResetColor();
            }
        }

        #endregion
    }
}
