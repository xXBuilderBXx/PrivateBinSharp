using System.Numerics;

namespace PrivateBinSharp;

internal static class Base58
{
	public const int CHECK_SUM_SIZE = 4;

	public const string ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	public static readonly BigInteger Base58BI = new BigInteger(58);
	public static readonly BigInteger Number256 = new BigInteger(256);

	private static readonly IReadOnlyDictionary<char, int> ALPHABET_DIC;

	static Base58()
	{
		ALPHABET_DIC = Enumerable
			.Range(0, ALPHABET.Length)
			.ToDictionary(t => ALPHABET[t], t => t);
	}

	#region Plain

	/// <summary>
	/// Encodes data in plain Base58, without any checksum
	/// </summary>
	/// <param name="input">The data to be encoded</param>
	/// <returns></returns>
	public static string EncodePlain(ICollection<byte> input)
	{
		BigInteger inputInteger;
		{
			inputInteger = BigInteger.Zero;
			// ReSharper disable once LoopCanBeConvertedToQuery
			foreach (var t in input)
			{
				inputInteger = inputInteger * Number256 + t;
			}
		}

		var result = "";
		while (inputInteger > 0)
		{
			var charOffset = (int)(inputInteger % Base58BI);
			result = ALPHABET[charOffset] + result;
			inputInteger /= Base58BI;
		}

		// ReSharper disable once LoopCanBeConvertedToQuery
		foreach (var t in input)
		{
			if (t != 0)
			{
				break;
			}

			result = "1" + result;
		}

		return result;
	}

	#endregion


}
