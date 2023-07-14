namespace PrivateBinSharp.Crypto.asn1;

// TODO[asn1] Should be renamed/replaced with DLSetParser
internal class DerSetParser
	: Asn1SetParser
{
	private readonly Asn1StreamParser m_parser;

	internal DerSetParser(Asn1StreamParser parser)
	{
		m_parser = parser;
	}

	public IAsn1Convertible ReadObject()
	{
		return m_parser.ReadObject();
	}

	public Asn1Object ToAsn1Object()
	{
		return DLSet.FromVector(m_parser.ReadVector());
	}
}
