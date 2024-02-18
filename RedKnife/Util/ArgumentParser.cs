using System;
using System.Collections.Generic;
using System.Reflection;

namespace Redknife.Util
{

    // Base interface for classes defining arguments
    public interface IArguments
    {

    }

    [System.AttributeUsage(System.AttributeTargets.Property, AllowMultiple = false)]
    public class ArgumentAttribute : Attribute
    {
        string Argument;
        public string Description;
        public bool Required;
        public string[] Values;
        public bool MultiValue;
        public char Delimeter;
        public Type ValuesEnum;

        public ArgumentAttribute(string Argument)
        {
            this.Argument = Argument;

            this.Description = "";
            this.Required = false;
            this.MultiValue = false;
            this.Delimeter = ',';
        }

        public string GetArgument() => this.Argument;
    }

    public class ArgumentParser<T> where T : IArguments, new()
    {

        private T parsedArgs;
        private Dictionary<string, PropertyInfo> mappedProperties;
        private Dictionary<string, ArgumentAttribute> mappedArguments;

        public ArgumentParser()
        {
            this.parsedArgs = new T();
            this.mappedProperties = new Dictionary<string, PropertyInfo>();
            this.mappedArguments = new Dictionary<string, ArgumentAttribute>();

            foreach (PropertyInfo propInfo in parsedArgs.GetType().GetProperties())
            {
                // Get the ArgumentAttribute for the property, if set
                ArgumentAttribute attr = this.GetPropertyArgumentAttribute(propInfo);

                if (attr == null) continue;

                this.mappedArguments.Add(attr.GetArgument(), attr);
                this.mappedProperties.Add(attr.GetArgument(), propInfo);
            }
        }

        protected ArgumentAttribute GetPropertyArgumentAttribute(PropertyInfo propInfo)
        {
            object[] customAttrs = propInfo.GetCustomAttributes(true);
            foreach(object objAttr in customAttrs)
            {
                if (objAttr.GetType() == typeof(ArgumentAttribute))
                {
                    return (ArgumentAttribute)objAttr;
                }
            }

            return null;
        }

        public T ParseArguments(string[] args)
        {

            // Loop through args
            for (int i = 0; i < args.Length; i++)
            {
                string currentArg = args[i];
                string currentVal = null;

                // Determine if arg supplied in arg=value form - need to split on equals and assign arg and val to vars
                if (currentArg.Contains("="))
                {
                    // arg name becomes everything up to first '=' char - val is everything after (may contain additional '=')
                    int firstEqualsPos = currentArg.IndexOf('=');
                    currentVal = currentArg.Substring(firstEqualsPos + 1);
                    currentArg = currentArg.Substring(0, firstEqualsPos);
                }

                // Check if arg is valid - throw exception if not
                this.CheckKnownArgument(currentArg);

                // Arg is valid - interrogate the corresponding property 
                PropertyInfo propInfo = this.mappedProperties[currentArg];

                // Check if current argument is a flag (special case)
                if (propInfo.PropertyType == typeof(bool))
                {
                    // Property is a flag - presence of argument indicates value of 'true'
                    this.mappedProperties[currentArg].SetValue(this.parsedArgs, true, null);
                    // No need to do anything further
                    continue;
                }

                // Anything other than a flag will need a value specified 
                // - this might have already been supplied if arg specified in arg=value format
                // If not, we'll need to grab the next argument in the array
                if (currentVal == null)
                {
                    currentVal = this.GetValueFromNextArg(currentArg, args, ++i);
                }

                // Actually parse the value and set it on the current parsedArgs
                if (propInfo.PropertyType == typeof(int) || propInfo.PropertyType == typeof(int?))
                {
                    this.ParseIntegerArgument(currentArg, currentVal);
                }
                else if (propInfo.PropertyType == typeof(string))
                {
                    this.ParseStringArgument(currentArg, currentVal);
                }
                else if (propInfo.PropertyType == typeof(string[]))
                {
                    this.ParseStringArrayArgument(currentArg, currentVal);
                }
                else
                {
                    throw new Exception("Don't know how to handle type for argument '" + currentArg + "': " + propInfo.PropertyType);
                }
            }

            return this.parsedArgs;
        }

        /**
         * Checks that the arugment (specified by param arg) is defined in the list of mappedProperties
         */
        protected void CheckKnownArgument(string arg)
        {
            if (!this.mappedProperties.ContainsKey(arg))
            {
                throw new Exception("Unknown argument: " + arg);
            }
        }

        protected string GetValueFromNextArg(string arg, string[] args, int nextIndex)
        {
            string val = null;

            // Check we have another arg to grab
            if (nextIndex >= args.Length)
            {
                throw new Exception("Expected value for argument: " + arg);
            }

            // Grab the next arg in the array
            val = args[nextIndex];

            // Check we've not grabbed a parameter by mistake  
            if (val.StartsWith("--"))
            {
                throw new Exception("Expected value for argument: " + arg);
            }

            // Got here, everything seems fine
            return val;
        }

        protected void ParseIntegerArgument(string arg, string val)
        {
            ArgumentAttribute argAttr = this.mappedArguments[arg];

            int parsedVal = 0;
            try
            {
                parsedVal = Int32.Parse(val);
            } catch (Exception ex)
            {
                throw new Exception(String.Format("Could not parse integer value for argument '{0}': {1}", arg, val));
            }

            this.mappedProperties[arg].SetValue(this.parsedArgs, parsedVal, null);
        }

        protected void ParseStringArgument(string arg, string val)
        {
            ArgumentAttribute argAttr = this.mappedArguments[arg];

            // if values set, validate supplied value is in the list
            if (argAttr.Values != null && Array.IndexOf(argAttr.Values, val) == -1)
            {
                throw new Exception("Invalid value for argument '" + arg + "': " + val);
            }

            this.mappedProperties[arg].SetValue(this.parsedArgs, val, null);
        }

        protected void ParseStringArrayArgument(string arg, string val)
        {
            ArgumentAttribute argAttr = this.mappedArguments[arg];

            string[] vals = val.Split(argAttr.Delimeter);

            // If attribute has values defined, check each value is valid
            if (argAttr.Values != null)
            {
                foreach (string tmpVal in vals)
                {
                    if (Array.IndexOf(argAttr.Values, tmpVal) == -1)
                    {
                        throw new Exception("Invalid value for argument '" + arg + "': " + tmpVal);
                    }
                }
            }

            // Got here, everything is valid - set the values on the property
            this.mappedProperties[arg].SetValue(this.parsedArgs, vals, null);
        }
    }

}
