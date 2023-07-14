namespace PrivateBinSharp.Crypto.security;

[Serializable]
internal class SecurityUtilityException
	: Exception
{
	public SecurityUtilityException(string message)
		: base(message)
	{
	}
}
