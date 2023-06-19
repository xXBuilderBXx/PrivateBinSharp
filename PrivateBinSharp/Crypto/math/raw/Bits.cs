using System.Diagnostics;
using System.Runtime.CompilerServices;


namespace PrivateBinSharp.Crypto.math.raw
{
    internal static class Bits
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint BitPermuteStep(uint x, uint m, int s)
        {
            Debug.Assert((m & m << s) == 0U);
            Debug.Assert(m << s >> s == m);

            uint t = (x ^ x >> s) & m;
            return t ^ t << s ^ x;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong BitPermuteStep(ulong x, ulong m, int s)
        {
            Debug.Assert((m & m << s) == 0UL);
            Debug.Assert(m << s >> s == m);

            ulong t = (x ^ x >> s) & m;
            return t ^ t << s ^ x;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong BitPermuteStepSimple(ulong x, ulong m, int s)
        {
            Debug.Assert(m << s == ~m);
            Debug.Assert((m & ~m) == 0UL);

            return (x & m) << s | x >> s & m;
        }
    }
}
