namespace PrivateBinSharp.Crypto.asn1;

internal class DerOutputStream
	: Asn1OutputStream
{
	internal DerOutputStream(Stream os, bool leaveOpen)
		: base(os, leaveOpen)
	{
	}

	internal override int Encoding
	{
		get { return EncodingDer; }
	}
}
