namespace PrivateBinSharp.Crypto.crypto.modes.gcm
{
    [Obsolete("Will be removed")]
    public interface IGcmExponentiator
    {
        void Init(byte[] x);
        void ExponentiateX(long pow, byte[] output);
    }
}
