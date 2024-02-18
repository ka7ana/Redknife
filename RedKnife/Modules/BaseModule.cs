using System;
using System.Collections.Generic;
using System.Text;

namespace Redknife.Modules
{
    public abstract class BaseModule
    {

        public RedknifeArgs Args { get; set; }
        public byte[] Payload { get; set; }

        public virtual void Validate()
        {
            
        }

        public abstract void Run();

    }
}
