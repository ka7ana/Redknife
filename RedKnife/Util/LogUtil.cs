using System;
using System.Collections.Generic;
using System.Text;

namespace Redknife
{

    public struct LogLevel
    {

        public LogLevel(int level, string symbol, string name)
        {
            Level = level;
            Symbol = symbol;
            Name = name;
        }

        public int Level { get; set; }
        public string Symbol{ get; set; }

        public string Name { get; set; }

    }

    public class LogUtil
    {

        private static string SEPARATOR = new string('=', 64);

        public static LogLevel DEBUG  = new LogLevel(0, ">", "DEBUG");
        public static LogLevel INFO = new LogLevel(1, "+", "INFO");
        public static LogLevel ERROR = new LogLevel(2, "!", "ERROR");
        public static LogLevel NONE = new LogLevel(3, "", "NONE");

        private static LogLevel CurrentLevel = INFO;

        public static void SetLogLevel(LogLevel level)
        {
            CurrentLevel = level;
        }

        public static LogLevel GetLogLevel()
        {
            return CurrentLevel;
        }

        public static void Debug(string message, int indent = 0, params object[] args)
        {
            Message(DEBUG, indent, message, args);
        }

        public static void Info(string message, int indent = 0, params object[] args)
        {
            Message(INFO, indent, message, args);
        }

        public static void Error(string message, int indent = 0, params object[] args)
        {
            Message(ERROR, indent, message, args);
        }


        public static void Message(LogLevel level, int indent, string message, object[] args)
        {
            // Check if we should log the message based on current log level
            if (level.Level < CurrentLevel.Level)
            {
                // message is lower log level than current
                return;
            }

            if (args != null && args.Length > 0)
            {
                message = String.Format(message, args);
            }
            string indentStr = GetIndent(indent);
            string line = String.Format("[{0}] {1}{2}", (indent > 0 ? "-" : level.Symbol), indentStr, message);
            Console.WriteLine(line);
        }

        public static string GetIndent(int indent)
        {
            return (indent <= 0 ? "" : new string(' ', indent * 2));
        }

        public static void Separator()
        {
            Console.WriteLine(SEPARATOR);
        }

        public static void PrintBlock(string message, string block)
        {
            Info(message);

            Separator();
            Console.WriteLine(block);
            Separator();
        }
    }
}
