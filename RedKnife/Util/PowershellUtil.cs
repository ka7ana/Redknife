using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Text.RegularExpressions;

namespace Redknife.Util
{
    public class PowershellUtil
    {

        public static void RunScript(string script)
        {
            LogUtil.Info("Attempting to execute PowerShell script: {0}", 0, script);

            if (script.Length % 4 == 0 && Regex.IsMatch(script, @"^[a-zA-Z0-9\+/]*={0,2}$"))
            {
                LogUtil.Info("Script is Base64 encoded, decoding...", 1);
                script = Encoding.UTF8.GetString(Convert.FromBase64String(script));

                LogUtil.Info("Decoded script: {0}", 1, script);
            }

            // Create the runspace
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            // Create the PowerShell instance
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            // Add and execute the script
            ps.AddScript(script);
            Collection<PSObject> returnObjects = ps.Invoke();

            LogUtil.Info("Script output:");

            // Iterate over the results, printing to console
            StringBuilder builder = new StringBuilder();
            foreach (PSObject obj in returnObjects)
            {
                builder.Append(obj.ToString());
            }
            Console.WriteLine(builder.ToString());

            LogUtil.Info("End of script output");

            // Close the runspace
            rs.Close();
        }

    }
}
