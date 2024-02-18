using System;
using System.Collections.Generic;
using System.Text;
using Redknife.Util;

namespace Redknife
{
    public class Transform
    {

        public static SortedSet<string> TRANSFORMATIONS = new SortedSet<string>()
        {
            "base64","xor","caesar","reverse"
        };

        public static byte[] DecodeBase64(string base64String)
        {
            return System.Convert.FromBase64String(base64String);
        }

        public static byte[] DecodeBase64(byte[] data)
        {
            char[] chars = System.Text.Encoding.ASCII.GetString(data).ToCharArray();
            return System.Convert.FromBase64CharArray(chars, 0, data.Length);
        }

        public static byte[] TransformBuffer(string transforms, byte[] buffer)
        {
            string[] transformsList = transforms.Split(',');
            return TransformBuffer(transformsList, buffer);
        }

        public static byte[] TransformBuffer(string[] transforms, byte[] buffer)
        {
            LogUtil.Debug("Initial buffer, before transformations:");
            PrintBuffer(buffer);

            foreach (string transform in transforms)
            {
                string tname = transform;
                string targ = null;

                // Transform might have an argument - split it out and get the name & arg
                if (transform.Contains("="))
                {
                    string[] parts = transform.Split('=');
                    tname = parts[0];
                    targ = parts[1];
                }
                switch (tname)
                {
                    case "base64":
                        buffer = DecodeBase64(buffer);
                        break;
                    case "xor":
                        buffer = Xor(buffer, targ);
                        break;
                    case "caesar":
                        buffer = Caesar(buffer, targ);
                        break;
                    case "reverse":
                        buffer = Reverse(buffer);
                        break;
                    case "b64":
                        break;
                    case "hex":
                        break;
                    default:
                        throw new Exception("Unsupported transformation: " + tname);
                }
                LogUtil.Debug("Finalised payload buffer:");
                PrintBuffer(buffer);
            }

            return buffer;
        }

        protected static byte[] Xor(byte[] buffer, string key)
        {
            LogUtil.Debug("Transforming buffer - XOR with key: " + key, 1);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] modified = new byte[buffer.Length];

            for (int i = 0; i < buffer.Length; i++)
            {
                modified[i] = (byte)(((uint)buffer[i] ^ (uint)keyBytes[i % keyBytes.Length]));
            }
            return modified;
        }

        protected static byte[] Caesar(byte[] buffer, string shiftString)
        {
            LogUtil.Debug("Transforming buffer - Caesar with key: " + shiftString, 1);
            int shift = Int16.Parse(shiftString);
            byte[] modified = new byte[buffer.Length];

            for (int i = 0; i < buffer.Length; i++)
            {
                modified[i] = (byte)((buffer[i] + shift) & 0xff);
            }
            return modified;
        }

        protected static byte[] Reverse(byte[] buffer)
        {
            LogUtil.Debug("Transforming buffer - Reversing", 1);
            byte[] modified = new byte[buffer.Length];
            for (int i = 0; i < buffer.Length; i++)
            {
                modified[i] = buffer[(buffer.Length - 1) - i];
            }
            return modified;
        }

        protected static void PrintBuffer(byte[] buffer)
        {
            if (LogUtil.GetLogLevel().Equals(LogUtil.DEBUG))
            {
                Console.WriteLine("BUFFER:");

                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < buffer.Length; i++)
                {
                    if (i > 0 && i % 16 == 0) hex.Append(System.Environment.NewLine);
                    hex.AppendFormat("{0:x2} ", buffer[i]);
                }
                Console.WriteLine(hex.ToString());
            }
        }

    }


}