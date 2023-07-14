using System.Runtime.Serialization;

namespace PrivateBinSharp.Crypto.asn1;

[Serializable]
internal class Asn1ParsingException
	: InvalidOperationException
{
	public Asn1ParsingException()
		: base()
	{
	}

	public Asn1ParsingException(string message)
		: base(message)
	{
	}

	public Asn1ParsingException(string message, Exception innerException)
		: base(message, innerException)
	{
	}

	protected Asn1ParsingException(SerializationInfo info, StreamingContext context)
		: base(info, context)
	{
	}
}
