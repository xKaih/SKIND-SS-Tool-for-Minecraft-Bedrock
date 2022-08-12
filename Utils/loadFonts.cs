using System;
using System.Drawing;
using System.Drawing.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SKIND_SS_Tool.Utils
{
    internal class loadFonts
    {
        //Imports and others
        [DllImport("gdi32.dll")]
        private static extern IntPtr AddFontMemResourceEx(IntPtr pbFont, uint cbFont,
            IntPtr pdv, [System.Runtime.InteropServices.In] ref uint pcFonts);

        private static PrivateFontCollection fonts = new PrivateFontCollection();
        public static uint numberOfFontAllocated = 0;

        //This method load the fonts from Resources on runtime
        public static void loadFontOnMemory(byte[] font)
        {
            byte[] fontData = font;
            IntPtr fontPtr = System.Runtime.InteropServices.Marshal.AllocCoTaskMem(fontData.Length);
            System.Runtime.InteropServices.Marshal.Copy(fontData, 0, fontPtr, fontData.Length);
            fonts.AddMemoryFont(fontPtr, font.Length);
            AddFontMemResourceEx(fontPtr, (uint)font.Length, IntPtr.Zero, ref numberOfFontAllocated);
            System.Runtime.InteropServices.Marshal.FreeCoTaskMem(fontPtr);

        }

        private static FontFamily getFontFamily(int family)
        {
            return fonts.Families[family];
        }
        //This will load the font to make it visible to the user  
        public static void loadFontsIntoControl(Control[] controls, int family)
        {
            foreach (Control control in controls)
            {
                control.Font = new Font(getFontFamily(family), control.Font.Size);
            }
        }
    }
}
