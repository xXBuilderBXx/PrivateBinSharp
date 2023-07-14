namespace PrivateBinSharp.Crypto.util.io;

[Serializable]
internal class StreamOverflowException
	: IOException
{
	public StreamOverflowException(string message)
		: base(message)
	{
	}
}
