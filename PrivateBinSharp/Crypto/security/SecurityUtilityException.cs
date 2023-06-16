using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.security
{
    [Serializable]
    public class SecurityUtilityException
        : Exception
    {
        public SecurityUtilityException()
            : base()
        {
        }

        public SecurityUtilityException(string message)
            : base(message)
        {
        }

        public SecurityUtilityException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected SecurityUtilityException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
