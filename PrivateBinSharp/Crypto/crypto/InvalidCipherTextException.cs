using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.crypto
{
    /// <summary>This exception is thrown whenever we find something we don't expect in a message.</summary>
    [Serializable]
    public class InvalidCipherTextException
        : CryptoException
    {
        public InvalidCipherTextException()
            : base()
        {
        }

        public InvalidCipherTextException(string message)
            : base(message)
        {
        }

        public InvalidCipherTextException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected InvalidCipherTextException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
