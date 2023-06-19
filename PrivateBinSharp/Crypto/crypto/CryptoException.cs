using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.crypto
{
    [Serializable]
    public class CryptoException
        : Exception
    {
        public CryptoException(string message)
            : base(message)
        {
        }
    }
}
