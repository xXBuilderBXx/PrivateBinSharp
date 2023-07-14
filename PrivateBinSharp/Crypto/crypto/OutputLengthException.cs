namespace PrivateBinSharp.Crypto.crypto;

[Serializable]
internal class OutputLengthException
	: DataLengthException
{
	public OutputLengthException(string message)
		: base(message)
	{
	}
}
