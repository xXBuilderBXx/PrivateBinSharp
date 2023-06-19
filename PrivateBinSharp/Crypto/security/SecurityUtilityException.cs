using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.security
{
    [Serializable]
    public class SecurityUtilityException
        : Exception
    {
        public SecurityUtilityException(string message)
            : base(message)
        {
        }
    }
}
