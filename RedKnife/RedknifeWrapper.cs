using System;
using System.IO;

namespace Redknife
{
    // Allow redknife to be run as an InstalUtil uninstaller
    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtilBypass : System.Configuration.Install.Installer
    {

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // Simply call main in RedknifeWrapper 
            RedknifeWrapper.Main(new string[0] { });
        }

    }

    public class RedknifeWrapper
    {

        public static void Main(string[] args)
        {
            StartRedknife(args);
        }

        public static void StartRedknife(string[] args)
        {
            Redknife redknife = new Redknife();

            try
            {
                // If we have no args provided, try and load args from predefined files
                if (args.Length == 0)
                {
                    LogUtil.Info("No arguments provided - checking for argument files");
                    string argsFromFile = GetArgumentsFromFile();
                    if (argsFromFile != null)
                    {
                        redknife.ParseArgumentsFromString(argsFromFile);
                    }
                    else
                    {
                        LogUtil.Info("No arguments provided, and no argument files found");
                        return;
                    }
                }
                else
                {
                    // Otherwise, just parse the cmd line args
                    redknife.ParseArguments(args);
                }
            }
            catch (Exception ex)
            {
                LogUtil.Error("ERROR - Could not parse command-line arguments: ");
                LogUtil.Error(ex.Message, 1);
                Environment.Exit(1);
            }

            // Args have been parsed, run!
            try
            {
                redknife.Run();
            }
            catch (Exception ex)
            {
                LogUtil.Error("ERROR - {0}", 0, ex.Message);
                LogUtil.Debug(ex.ToString());
                Environment.Exit(1);
            }
        }

        protected static string GetArgumentsFromFile()
        {
            // Get the current process name
            string appName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            string temp = System.IO.Path.GetTempPath();

            // Attempt to read args from file (named either redknife.txt or APPNAME.txt)
            // 1. in current directory
            // 2. in current temp directory
            // 3. in C:\

            // Check local dir
            string content = GetFileContents("redknife.txt");
            if (content == null && !appName.Equals("redknife")) content = GetFileContents(appName + ".txt");

            // Check temp
            if (content == null) content = GetFileContents(Path.Combine(temp, "redknife.txt"));
            if (content == null && !appName.Equals("redknife")) content = GetFileContents(Path.Combine(temp, appName + ".txt"));

            // Check C:\
            if (content == null) content = GetFileContents("C:\\redknife.txt");
            if (content == null && !appName.Equals("redknife")) content = GetFileContents("C:\\" + appName + ".txt");

            return content;
        }

        protected static string GetFileContents(string path)
        {
            LogUtil.Info("Checking for arg file at path: {0}", 1, path);
            if (File.Exists(path))
            {
                LogUtil.Info("Found! Reading args from file", 2);
                return File.ReadAllText(path);
            }
            return null;
        }
    }
}
