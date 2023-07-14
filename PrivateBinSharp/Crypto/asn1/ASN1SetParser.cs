namespace PrivateBinSharp.Crypto.asn1;

internal interface Asn1SetParser
	: IAsn1Convertible
{
	IAsn1Convertible ReadObject();
}
