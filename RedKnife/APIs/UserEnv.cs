using System;
using System.Runtime.InteropServices;

namespace Redknife.APIs
{
    public class UserEnv
    {

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    }
}
