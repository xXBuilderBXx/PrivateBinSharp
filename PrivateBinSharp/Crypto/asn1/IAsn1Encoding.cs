namespace PrivateBinSharp.Crypto.asn1
{
    internal interface IAsn1Encoding
    {
        void Encode(Asn1OutputStream asn1Out);

        int GetLength();
    }
}
