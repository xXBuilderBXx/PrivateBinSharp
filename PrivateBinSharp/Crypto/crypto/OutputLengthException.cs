using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.crypto
{
    [Serializable]
    public class OutputLengthException
        : DataLengthException
    {
        public OutputLengthException(string message)
            : base(message)
        {
        }
    }
}
