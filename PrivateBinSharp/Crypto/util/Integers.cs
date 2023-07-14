using System.Numerics;


namespace PrivateBinSharp.Crypto.util;

internal static class Integers
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
