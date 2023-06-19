using System.Diagnostics;

namespace PrivateBinSharp.Crypto.math.raw
{
    /*
     * Modular inversion as implemented in this class is based on the paper "Fast constant-time gcd
     * computation and modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
     */

    internal static class Mod
    {
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

    }
}
