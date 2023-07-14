namespace PrivateBinSharp.Crypto.asn1;

internal class BerSetParser
	: Asn1SetParser
{
	private readonly Asn1StreamParser _parser;

	internal BerSetParser(Asn1StreamParser parser)
	{
		_parser = parser;
	}

	public IAsn1Convertible ReadObject()
	{
		return _parser.ReadObject();
	}

	public Asn1Object ToAsn1Object()
	{
		return Parse(_parser);
	}

	internal static BerSet Parse(Asn1StreamParser sp)
	{
		return new BerSet(sp.ReadVector());
	}
}
