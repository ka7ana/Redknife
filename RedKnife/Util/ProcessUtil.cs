using System;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Redknife.Util
{
    public class ProcessUtil
    {

        private static string PROCESS_INFO_REGEX = @"(?<exe>""[^""]+""|[^ ]+) ?(?<args>.*)?";

        public static ProcessStartInfo ParseCommandLineAsProcessInfo(string cmdLine)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo();

            Regex rx = new Regex(PROCESS_INFO_REGEX, RegexOptions.Compiled);
            MatchCollection matches = rx.Matches(cmdLine);
            if (matches.Count > 0)
            {
                Match match = matches[0];
                processInfo.FileName = match.Groups["exe"].Value;
                processInfo.Arguments = match.Groups["args"].Value;
            } 
            else
            {
                throw new Exception("No match for input");
            }

            return processInfo;
        }

    }
}
