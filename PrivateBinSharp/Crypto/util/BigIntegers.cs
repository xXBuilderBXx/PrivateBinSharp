using PrivateBinSharp.Crypto.math;
using PrivateBinSharp.Crypto.security;

namespace PrivateBinSharp.Crypto.util;

/**
     * BigInteger utilities.
     */
internal static class BigIntegers
{
	public static readonly BigInteger Zero = BigInteger.Zero;
	public static readonly BigInteger One = BigInteger.One;

	private const int MaxIterations = 1000;

	/**
        * Return a random BigInteger not less than 'min' and not greater than 'max'
        * 
        * @param min the least value that may be generated
        * @param max the greatest value that may be generated
        * @param random the source of randomness
        * @return a random BigInteger value in the range [min,max]
        */
	public static BigInteger CreateRandomInRange(BigInteger min, BigInteger max, SecureRandom random)
	{
		int cmp = min.CompareTo(max);
		if (cmp >= 0)
		{
			if (cmp > 0)
				throw new ArgumentException("'min' may not be greater than 'max'");

			return min;
		}

		if (min.BitLength > max.BitLength / 2)
			return CreateRandomInRange(BigInteger.Zero, max.Subtract(min), random).Add(min);

		for (int i = 0; i < MaxIterations; ++i)
		{
			BigInteger x = new BigInteger(max.BitLength, random);
			if (x.CompareTo(min) >= 0 && x.CompareTo(max) <= 0)
				return x;
		}

		// fall back to a faster (restricted) method
		return new BigInteger(max.Subtract(min).BitLength - 1, random).Add(min);
	}

	public static int GetByteLength(BigInteger n)
	{
		return n.GetLengthofByteArray();
	}
}
