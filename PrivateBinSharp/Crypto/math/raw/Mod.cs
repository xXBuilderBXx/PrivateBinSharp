using System.Diagnostics;

namespace PrivateBinSharp.Crypto.math.raw
{
    /*
     * Modular inversion as implemented in this class is based on the paper "Fast constant-time gcd
     * computation and modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
     */

    internal static class Mod
    {

        //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        //        public static void CheckedModOddInverse(ReadOnlySpan<uint> m, ReadOnlySpan<uint> x, Span<uint> z)
        //#else
        //        public static void CheckedModOddInverse(uint[] m, uint[] x, uint[] z)
        //#endif
        //        {
        //            if (0 == ModOddInverse(m, x, z))
        //                throw new ArithmeticException("Inverse does not exist.");
        //        }

        //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        //        public static void CheckedModOddInverseVar(ReadOnlySpan<uint> m, ReadOnlySpan<uint> x, Span<uint> z)
        //#else
        //        public static void CheckedModOddInverseVar(uint[] m, uint[] x, uint[] z)
        //#endif
        //        {
        //            if (!ModOddInverseVar(m, x, z))
        //                throw new ArithmeticException("Inverse does not exist.");
        //        }

        public static uint Inverse32(uint d)
        {
            Debug.Assert((d & 1U) == 1U);

            //int x = d + (((d + 1) & 4) << 1);   // d.x == 1 mod 2**4
            uint x = d;                         // d.x == 1 mod 2**3
            x *= 2 - d * x;                     // d.x == 1 mod 2**6
            x *= 2 - d * x;                     // d.x == 1 mod 2**12
            x *= 2 - d * x;                     // d.x == 1 mod 2**24
            x *= 2 - d * x;                     // d.x == 1 mod 2**48
            Debug.Assert(d * x == 1U);
            return x;
        }

        public static ulong Inverse64(ulong d)
        {
            Debug.Assert((d & 1UL) == 1UL);

            //ulong x = d + (((d + 1) & 4) << 1);   // d.x == 1 mod 2**4
            ulong x = d;                            // d.x == 1 mod 2**3
            x *= 2 - d * x;                         // d.x == 1 mod 2**6
            x *= 2 - d * x;                         // d.x == 1 mod 2**12
            x *= 2 - d * x;                         // d.x == 1 mod 2**24
            x *= 2 - d * x;                         // d.x == 1 mod 2**48
            x *= 2 - d * x;                         // d.x == 1 mod 2**96
            Debug.Assert(d * x == 1UL);
            return x;
        }
    }
}
