namespace PrivateBinSharp.Crypto.crypto;

[Serializable]
internal class CryptoException
	: Exception
{
	public CryptoException(string message)
		: base(message)
	{
	}
}
