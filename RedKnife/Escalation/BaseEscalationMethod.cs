using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Redknife.Escalation
{
    public class BaseEscalationMethod
    {

        protected RedknifeArgs args;

        public BaseEscalationMethod(RedknifeArgs args)
        {
            this.args = args;
        }

        public virtual void Validate()
        {

        }

        public virtual void Execute()
        {

        }

        public bool ShouldStopExecution()
        {
            return false;
        }

    }
}
