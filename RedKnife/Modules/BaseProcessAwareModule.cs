using System;
using System.Diagnostics;

namespace Redknife.Modules
{
    public abstract class BaseProcessAwareModule : BaseModule
    {

        protected Process TargetProcess { get; set; }

        public override void Validate()
        {
            if (!this.Args.PID.HasValue && this.Args.ProcessName == null)
            {
                throw new Exception("PID or Process name must be supplied");
            }

            // If name set, attempt to get PID from process name
            if (this.Args.ProcessName != null)
            {
                LogUtil.Debug("Process to operate on specified by name: {0}. Attempting to get process PID...", 0, this.Args.ProcessName);
                // Get the pid of the process
                var processes = Process.GetProcessesByName(this.Args.ProcessName);
                if (processes == null || processes.Length == 0)
                {
                    throw new Exception("No process named '" + this.Args.ProcessName + "'");
                }
                this.Args.PID = processes[0].Id;
                LogUtil.Debug("Process {0}: PID = {1}", 1, this.Args.ProcessName, this.Args.PID);
            }

            // Check we have a valid PID
            if (!this.Args.PID.HasValue || this.Args.PID < 0)
            {
                throw new Exception("Invalid PID to inject into, PID: " + this.Args.PID);
            }

            // Try and get the process
            Process process = Process.GetProcessById(this.Args.PID.Value);
            if (process == null)
            {
                throw new Exception("Could not get process ID: " + this.Args.PID);
            }
            this.TargetProcess = process;

            // If we didn't have the process name specified, set it now
            if (this.Args.ProcessName == null)
            {
                this.Args.ProcessName = this.TargetProcess.ProcessName;
            }
        }

    }
}
