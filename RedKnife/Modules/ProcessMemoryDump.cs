using System;
using System.IO;

using Redknife.APIs;

namespace Redknife.Modules
{
    public class ProcessMemoryDump : BaseProcessAwareModule
    {

        public override void Run()
        {
            LogUtil.Debug("Attempting to dump memory for process '{0}' (PID: {1})", 0, this.Args.ProcessName, this.Args.PID);

            // Work out where to save the dump
            string outputPath = this.GetOutputFile();
            LogUtil.Debug("Writing dump file to path: {0}", 1, outputPath);
            FileStream dumpFile = new FileStream(outputPath, FileMode.Create);

            // Open the target process
            LogUtil.Debug("Opening target process...", 1);
            IntPtr handle = Kernel32.OpenProcess(0x001F0FFF, false, this.TargetProcess.Id);

            // Dump the process memory to the specified file
            LogUtil.Debug("Dumping process memory to file...", 1);
            bool dumped = Dbghelp.MiniDumpWriteDump(handle, this.TargetProcess.Id, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (dumped)
            {
                LogUtil.Debug("Successfully dumped process '{0}' (PID: {1}) memory to file", 0, this.Args.ProcessName, this.Args.PID);
            }
            else
            {
                LogUtil.Debug("Could not dump process '{0}' (PID: {1}) memory to file", 0, this.Args.ProcessName, this.Args.PID);
            }
        }

        protected string GetOutputFile()
        {
            string outputDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string outputFile = String.Format("Process_{0}_{1}.dmp", this.Args.ProcessName, System.DateTime.Now.ToString("yyyyMMdd'-'HHmmss"));
            
            string outputPath = Path.Combine(outputDir, outputFile);

            if (this.Args.OutputFile != null)
            {
                // Is outputFile a directory? Use default file name and write to specified dir
                if (Directory.Exists(this.Args.OutputFile))
                {
                    outputPath = Path.Combine(this.Args.OutputFile, outputFile);
                }
                else
                {
                    // Otherwise, use OutputFile verbatim
                    outputPath = this.Args.OutputFile;
                }
            }

            return outputPath;
        }
    }
}
