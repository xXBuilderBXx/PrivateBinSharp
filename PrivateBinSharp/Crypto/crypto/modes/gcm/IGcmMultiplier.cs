namespace PrivateBinSharp.Crypto.crypto.modes.gcm
{
    [Obsolete("Will be removed")]
    public interface IGcmMultiplier
    {
        void Init(byte[] H);
        void MultiplyH(byte[] x);
    }
}
