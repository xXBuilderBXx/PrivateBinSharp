using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.util.io
{
    [Serializable]
    public class StreamOverflowException
        : IOException
    {
        public StreamOverflowException(string message)
            : base(message)
        {
        }
    }
}
