using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.asn1;

[Serializable]
internal class Asn1Exception
	: IOException
{
	public Asn1Exception()
		: base()
	{
	}

	public Asn1Exception(string message)
		: base(message)
	{
	}

	public Asn1Exception(string message, Exception innerException)
		: base(message, innerException)
	{
	}

	protected Asn1Exception(SerializationInfo info, StreamingContext context)
		: base(info, context)
	{
	}
}
