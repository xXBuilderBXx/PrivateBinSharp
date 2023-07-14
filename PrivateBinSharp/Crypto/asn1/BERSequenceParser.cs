namespace PrivateBinSharp.Crypto.asn1;

internal class BerSequenceParser
	: Asn1SequenceParser
{
	private readonly Asn1StreamParser _parser;

	internal BerSequenceParser(Asn1StreamParser parser)
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

	internal static BerSequence Parse(Asn1StreamParser sp)
	{
		return new BerSequence(sp.ReadVector());
	}
}
