#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Numerics;
#endif


namespace PrivateBinSharp.Crypto.util
{
    public static class Integers
    {
        public const int NumBits = 32;
        public const int NumBytes = 4;

        public static int NumberOfLeadingZeros(int i)
        {
            return BitOperations.LeadingZeroCount((uint)i);
        }

        public static int PopCount(uint u)
        {
            return BitOperations.PopCount(u);
        }
    }
}
