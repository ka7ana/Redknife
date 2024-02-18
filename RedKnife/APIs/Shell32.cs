using System;
using System.Runtime.InteropServices;

namespace Redknife.APIs
{
    public class Shell32
    {

        [DllImport("shell32.dll", SetLastError = true)]
        public static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);
    }
}
