using System.Runtime.Intrinsics.X86;

namespace PrivateBinSharp.Crypto.crypto.modes.gcm
{
    [Obsolete("Will be removed")]
    public class BasicGcmMultiplier
        : IGcmMultiplier
    {
        internal static bool IsHardwareAccelerated => Pclmulqdq.IsSupported;

        private GcmUtilities.FieldElement H;

        public void Init(byte[] H)
        {
            GcmUtilities.AsFieldElement(H, out this.H);
        }

        public void MultiplyH(byte[] x)
        {
            GcmUtilities.AsFieldElement(x, out var T);
            GcmUtilities.Multiply(ref T, ref H);
            GcmUtilities.AsBytes(ref T, x);
        }
    }
}
