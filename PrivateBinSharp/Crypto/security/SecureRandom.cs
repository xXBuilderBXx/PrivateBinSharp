using PrivateBinSharp.Crypto.crypto;
using PrivateBinSharp.Crypto.crypto.prng;
using PrivateBinSharp.Crypto.util;

namespace PrivateBinSharp.Crypto.security;

internal class SecureRandom
	: Random
{
	private static long counter = DateTime.UtcNow.Ticks;

	private static long NextCounterValue()
	{
		return Interlocked.Increment(ref counter);
	}

	private static readonly SecureRandom MasterRandom = new SecureRandom(new CryptoApiRandomGenerator());
	internal static readonly SecureRandom ArbitraryRandom = new SecureRandom(new VmpcRandomGenerator(), 16);

	private static DigestRandomGenerator? CreatePrng(string digestName, bool autoSeed)
	{
		IDigest digest = DigestUtilities.GetDigest(digestName);
		if (digest == null)
			return null;
		DigestRandomGenerator prng = new DigestRandomGenerator(digest);
		if (autoSeed)
		{
			AutoSeed(prng, 2 * digest.GetDigestSize());
		}
		return prng;
	}

	public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
	{
		byte[] result = new byte[length];
		secureRandom.NextBytes(result);
		return result;
	}

	protected readonly IRandomGenerator generator;

	public SecureRandom()
		: this(CreatePrng("SHA256", true)!)
	{
	}

	/// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
	/// <remarks>
	/// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
	/// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
	/// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
	/// implementation.
	/// </remarks>
	/// <param name="generator">The source to generate all random bytes from.</param>
	public SecureRandom(IRandomGenerator generator)
		: base(0)
	{
		this.generator = generator;
	}

	public SecureRandom(IRandomGenerator generator, int autoSeedLengthInBytes)
		: base(0)
	{
		AutoSeed(generator, autoSeedLengthInBytes);

		this.generator = generator;
	}

	public override int Next(int maxValue)
	{
		if (maxValue < 2)
		{
			if (maxValue < 0)
				throw new ArgumentOutOfRangeException("maxValue", "cannot be negative");

			return 0;
		}

		int bits;

		// Test whether maxValue is a power of 2
		if ((maxValue & maxValue - 1) == 0)
		{
			bits = NextInt() & int.MaxValue;
			return (int)((long)bits * maxValue >> 31);
		}

		int result;
		do
		{
			bits = NextInt() & int.MaxValue;
			result = bits % maxValue;
		}
		while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

		return result;
	}

	public override void NextBytes(byte[] buf)
	{
		generator.NextBytes(buf);
	}

	public override void NextBytes(Span<byte> buffer)
	{
		if (generator != null)
		{
			generator.NextBytes(buffer);
		}
		else
		{
			byte[] tmp = new byte[buffer.Length];
			NextBytes(tmp);
			tmp.CopyTo(buffer);
		}
	}

	private static readonly double DoubleScale = 1.0 / Convert.ToDouble(1L << 53);


	public virtual int NextInt()
	{
		Span<byte> bytes = stackalloc byte[4];
		NextBytes(bytes);
		return (int)Pack.BE_To_UInt32(bytes);
	}


	private static void AutoSeed(IRandomGenerator generator, int seedLength)
	{
		generator.AddSeedMaterial(NextCounterValue());
		Span<byte> seed = seedLength <= 128
			? stackalloc byte[seedLength]
			: new byte[seedLength];
		MasterRandom.NextBytes(seed);
		generator.AddSeedMaterial(seed);
	}
}
