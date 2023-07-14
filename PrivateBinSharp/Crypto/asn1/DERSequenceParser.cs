namespace PrivateBinSharp.Crypto.asn1;

// TODO[asn1] Should be renamed/replaced with DLSequenceParser
internal class DerSequenceParser
	: Asn1SequenceParser
{
	private readonly Asn1StreamParser m_parser;

	internal DerSequenceParser(Asn1StreamParser parser)
	{
		m_parser = parser;
	}

	public IAsn1Convertible ReadObject()
	{
		return m_parser.ReadObject();
	}

	public Asn1Object ToAsn1Object()
	{
		return DLSequence.FromVector(m_parser.ReadVector());
	}
}
