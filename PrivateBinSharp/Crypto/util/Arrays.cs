using System.Security.Cryptography;

namespace PrivateBinSharp.Crypto.util;

/// <summary> General array utilities.</summary>
internal static class Arrays
{
	public static readonly byte[] EmptyBytes = Array.Empty<byte>();
	public static readonly int[] EmptyInts = Array.Empty<int>();

	/// <summary>
	/// Are two arrays equal.
	/// </summary>
	/// <param name="a">Left side.</param>
	/// <param name="b">Right side.</param>
	/// <returns>True if equal.</returns>
	public static bool AreEqual(byte[] a, byte[] b)
	{
		if (a == b)
			return true;

		if (a == null || b == null)
			return false;

		return HaveSameContents(a, b);
	}

	public static bool FixedTimeEquals(byte[] a, byte[] b)
	{
		if (null == a || null == b)
			return false;

		return CryptographicOperations.FixedTimeEquals(a, b);
	}

	public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
	{
		return CryptographicOperations.FixedTimeEquals(a, b);
	}

	private static bool HaveSameContents(
		byte[] a,
		byte[] b)
	{
		int i = a.Length;
		if (i != b.Length)
			return false;
		while (i != 0)
		{
			--i;
			if (a[i] != b[i])
				return false;
		}
		return true;
	}

	public static int GetHashCode(byte[] data)
	{
		if (data == null)
		{
			return 0;
		}

		int i = data.Length;
		int hc = i + 1;

		while (--i >= 0)
		{
			hc *= 257;
			hc ^= data[i];
		}

		return hc;
	}

	public static int GetHashCode(byte[] data, int off, int len)
	{
		if (data == null)
		{
			return 0;
		}

		int i = len;
		int hc = i + 1;

		while (--i >= 0)
		{
			hc *= 257;
			hc ^= data[off + i];
		}

		return hc;
	}

	public static byte[] Clone(byte[] data)
	{
		return data == null ? null : (byte[])data.Clone();
	}

	public static uint[] Clone(uint[] data)
	{
		return data == null ? null : (uint[])data.Clone();
	}

	public static void Fill(byte[] buf, byte b)
	{
		int i = buf.Length;
		while (i > 0)
		{
			buf[--i] = b;
		}
	}
	/**
         * Make a copy of a range of bytes from the passed in data array. The range can
         * extend beyond the end of the input array, in which case the return array will
         * be padded with zeroes.
         *
         * @param data the array from which the data is to be copied.
         * @param from the start index at which the copying should take place.
         * @param to the final index of the range (exclusive).
         *
         * @return a new byte array containing the range given.
         */
	public static byte[] CopyOfRange(byte[] data, int from, int to)
	{
		int newLength = GetLength(from, to);
		byte[] tmp = new byte[newLength];
		Array.Copy(data, from, tmp, 0, Math.Min(newLength, data.Length - from));
		return tmp;
	}

	private static int GetLength(int from, int to)
	{
		int newLength = to - from;
		if (newLength < 0)
			throw new ArgumentException(from + " > " + to);
		return newLength;
	}
	public static byte[] Prepend(byte[] a, byte b)
	{
		if (a == null)
			return new byte[] { b };

		int length = a.Length;
		byte[] result = new byte[length + 1];
		Array.Copy(a, 0, result, 1, length);
		result[0] = b;
		return result;
	}

	internal static void Reverse<T>(T[] input, T[] output)
	{
		int last = input.Length - 1;
		for (int i = 0; i <= last; ++i)
		{
			output[i] = input[last - i];
		}
	}


	public static bool IsNullOrContainsNull(object[] array)
	{
		if (null == array)
			return true;

		int count = array.Length;
		for (int i = 0; i < count; ++i)
		{
			if (null == array[i])
				return true;
		}
		return false;
	}

	public static bool IsNullOrEmpty(byte[] array)
	{
		return null == array || array.Length < 1;
	}

	public static T[] Prepend<T>(ReadOnlySpan<T> a, T b)
	{
		T[] result = new T[1 + a.Length];
		result[0] = b;
		a.CopyTo(result.AsSpan(1));
		return result;
	}
}
