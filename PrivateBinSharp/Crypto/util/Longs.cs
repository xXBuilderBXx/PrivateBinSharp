using PrivateBinSharp.Crypto.math.raw;
using System.Buffers.Binary;

namespace PrivateBinSharp.Crypto.util;

internal static class Longs
{
	public const int NumBits = 64;
	public const int NumBytes = 8;

	public static ulong Reverse(ulong i)
	{
		i = Bits.BitPermuteStepSimple(i, 0x5555555555555555UL, 1);
		i = Bits.BitPermuteStepSimple(i, 0x3333333333333333UL, 2);
		i = Bits.BitPermuteStepSimple(i, 0x0F0F0F0F0F0F0F0FUL, 4);
		return ReverseBytes(i);
	}

	public static ulong ReverseBytes(ulong i)
	{
		return BinaryPrimitives.ReverseEndianness(i);
	}
}
