using System;
using System.Runtime.InteropServices;

namespace Redknife.APIs
{
    public class Dbghelp
    {

        [DllImport("Dbghelp.dll")]
        public static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId,
          IntPtr hFile, int DumpType, IntPtr ExceptionParam,
          IntPtr UserStreamParam, IntPtr CallbackParam);


    }
}
