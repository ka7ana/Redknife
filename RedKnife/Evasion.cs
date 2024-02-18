using System;
using Redknife.APIs;

namespace Redknife
{
    class Evasion
    {
        public static bool TestSleep(uint mls)
        {
            LogUtil.Debug("Evasion - attempting to sleep for {0} milliseconds", 0, mls);

            DateTime t1 = DateTime.Now;
            Kernel32.Sleep(mls);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            double tolerance = (mls - 500) / 1000;
            return (t2 < tolerance);
        }

        /**
         * Returns true if value returned from FlsAlloc was 0xFFFFFFFF (i.e. call failed) 
         */
        public static bool TestFlsAlloc()
        {
            LogUtil.Debug("Evasion - attempting to call FlsAllocate");

            UInt32 result = Kernel32.FlsAlloc(IntPtr.Zero);
            return (result == 0xFFFFFFFF);
        }
    }
}
