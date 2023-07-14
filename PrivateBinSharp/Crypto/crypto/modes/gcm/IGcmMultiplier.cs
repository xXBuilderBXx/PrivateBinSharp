namespace PrivateBinSharp.Crypto.crypto.modes.gcm;

[Obsolete("Will be removed")]
internal interface IGcmMultiplier
{
	void Init(byte[] H);
	void MultiplyH(byte[] x);
}
