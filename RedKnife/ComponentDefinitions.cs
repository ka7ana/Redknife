using System;
using System.Reflection;

namespace Redknife
{

    public class ModuleAttribute : Attribute
    {

        public string Name { get; private set; }

        public Type Type { get; private set; }

        public string Description { get; private set; }

        public string[] RequiredParameters { get; set; }

        internal ModuleAttribute(string name, Type componentType, string description)
        {
            this.Name = name;
            this.Type = componentType;
            this.Description = description;

            this.RequiredParameters = null;
        }

    }

    public static class ModuleAttributes
    {

        public static string GetName(this ModuleDefinition module)
        {
            ModuleAttribute attr = GetAttr(module);
            return attr.Name;
        }

        public static Type GetModuleType(this ModuleDefinition module)
        {
            ModuleAttribute attr = GetAttr(module);
            return attr.Type;
        }

        private static ModuleAttribute GetAttr(ModuleDefinition module)
        {
            return (ModuleAttribute)Attribute.GetCustomAttribute(ForValue(module), typeof(ModuleAttribute));
        }

        private static MemberInfo ForValue(ModuleDefinition module)
        {
            return typeof(ModuleDefinition).GetField(Enum.GetName(typeof(ModuleDefinition), module));
        }
    }

    public enum ModuleDefinition
    {
        [ModuleAttribute("exec-ps", typeof(Modules.PowerShellScript), "Execute PowerShell script within custom Runspace")]
        POWERSHELL_SCRIPT,

        [ModuleAttribute("new-thread", typeof(Modules.SpawnNewThread), "Spawn a new thread in the current (Redknife) process")]
        SPAWN_NEW_THREAD,

        [ModuleAttribute("process-inject", typeof(Modules.SimpleProcessInjection), "Inject payload and create thread in process defined by --pid or --process parameter")]
        PROCESS_INJECTION,

        [ModuleAttribute("nt-process-inject", typeof(Modules.NtProcessInjection), "Inject payload and create thread in process (using NtDLL methods) defined by --pid or --process parameter")]
        NT_PROCESS_INJECTION,

        [ModuleAttribute("process-hollow", typeof(Modules.ProcessHollower), "Starts an instance of svchost.exe, which is then hollowed and replaced with payload")]
        PROCESS_HOLLOWING,

        [ModuleAttribute("shell-cmd", typeof(Modules.ExecuteShellCommand), "Execute a shell command (defined in the payload, as specified by either --file, --url or --payload parameters)")]
        EXECUTE_SHELL_COMMAND,

        [ModuleAttribute("process-dump", typeof(Modules.ProcessMemoryDump), "Dump a process' memory. Specify the ID or name of the process to dump via the --pid or --process arguments respectively. The output file can be controlled via --output-file (otherwise defaults to %TEMP%)")]
        PROCESS_DUMP,

        [ModuleAttribute("rdp-thief", typeof(Modules.RDPThief), "Inject the RDPThief.dll into running mstsc processes. The payload passed to the module must represent the path to the RDPThief.dll on the target system (this is not written by Redknife) ")]
        RDP_THIEF,

        [ModuleAttribute("hijack-remote-service", typeof(Modules.HijackRemoteService), "Lateral movement via reconfiguration of a remote service. Current user should have permission to edit the service on the remote host. Use --service-name to specify service, --host-name to specify remote machine")]
        HIJACK_REMOTE_SERVICE
    }
}
