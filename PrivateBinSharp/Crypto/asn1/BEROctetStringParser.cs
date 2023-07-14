using PrivateBinSharp.Crypto.util.io;

namespace PrivateBinSharp.Crypto.asn1;

internal class BerOctetStringParser
	: Asn1OctetStringParser
{
	private readonly Asn1StreamParser _parser;

	internal BerOctetStringParser(Asn1StreamParser parser)
	{
		_parser = parser;
	}

	public Stream GetOctetStream()
	{
		return new ConstructedOctetStream(_parser);
	}

	public Asn1Object ToAsn1Object()
	{
		try
		{
			return Parse(_parser);
		}
		catch (IOException e)
		{
			throw new Asn1ParsingException("IOException converting stream to byte array: " + e.Message, e);
		}
	}

	internal static BerOctetString Parse(Asn1StreamParser sp)
	{
		return new BerOctetString(Streams.ReadAll(new ConstructedOctetStream(sp)));
	}
}
