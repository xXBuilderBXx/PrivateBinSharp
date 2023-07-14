using PrivateBinSharp.Crypto.asn1;
using PrivateBinSharp.Crypto.asn1.nist;
using PrivateBinSharp.Crypto.crypto;
using PrivateBinSharp.Crypto.crypto.digests;
using PrivateBinSharp.Crypto.util;
using PrivateBinSharp.Crypto.util.collections;

namespace PrivateBinSharp.Crypto.security;

/// <remarks>
///  Utility class for creating IDigest objects from their names/Oids
/// </remarks>
internal static class DigestUtilities
{
	private enum DigestAlgorithm
	{
		BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512,
		BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256,
		BLAKE3_256,
		DSTU7564_256, DSTU7564_384, DSTU7564_512,
		GOST3411,
		GOST3411_2012_256, GOST3411_2012_512,
		KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512,
		MD2, MD4, MD5,
		NONE,
		RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320,
		SHA_1, SHA_224, SHA_256, SHA_384, SHA_512,
		SHA_512_224, SHA_512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512,
		SHAKE128_256, SHAKE256_512,
		SM3,
		TIGER,
		WHIRLPOOL,
	};

	private static readonly IDictionary<string, string> Aliases =
		new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
	private static readonly IDictionary<string, DerObjectIdentifier> Oids =
		new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);

	static DigestUtilities()
	{
		// Signal to obfuscation tools not to change enum constants
		Enums.GetArbitraryValue<DigestAlgorithm>().ToString();

		Aliases["SHA1"] = "SHA-1";
		Aliases["SHA224"] = "SHA-224";
		Aliases[NistObjectIdentifiers.IdSha224.Id] = "SHA-224";
		Aliases["SHA256"] = "SHA-256";
		Aliases[NistObjectIdentifiers.IdSha256.Id] = "SHA-256";
		Aliases["SHA384"] = "SHA-384";
		Aliases[NistObjectIdentifiers.IdSha384.Id] = "SHA-384";
		Aliases["SHA512"] = "SHA-512";
		Aliases[NistObjectIdentifiers.IdSha512.Id] = "SHA-512";

		Aliases["SHA512/224"] = "SHA-512/224";
		Aliases["SHA512(224)"] = "SHA-512/224";
		Aliases["SHA-512(224)"] = "SHA-512/224";
		Aliases[NistObjectIdentifiers.IdSha512_224.Id] = "SHA-512/224";
		Aliases["SHA512/256"] = "SHA-512/256";
		Aliases["SHA512(256)"] = "SHA-512/256";
		Aliases["SHA-512(256)"] = "SHA-512/256";
		Aliases[NistObjectIdentifiers.IdSha512_256.Id] = "SHA-512/256";

		Aliases["KECCAK224"] = "KECCAK-224";
		Aliases["KECCAK256"] = "KECCAK-256";
		Aliases["KECCAK288"] = "KECCAK-288";
		Aliases["KECCAK384"] = "KECCAK-384";
		Aliases["KECCAK512"] = "KECCAK-512";

		Aliases[NistObjectIdentifiers.IdSha3_224.Id] = "SHA3-224";
		Aliases[NistObjectIdentifiers.IdHMacWithSha3_224.Id] = "SHA3-224";
		Aliases[NistObjectIdentifiers.IdSha3_256.Id] = "SHA3-256";
		Aliases[NistObjectIdentifiers.IdHMacWithSha3_256.Id] = "SHA3-256";
		Aliases[NistObjectIdentifiers.IdSha3_384.Id] = "SHA3-384";
		Aliases[NistObjectIdentifiers.IdHMacWithSha3_384.Id] = "SHA3-384";
		Aliases[NistObjectIdentifiers.IdSha3_512.Id] = "SHA3-512";
		Aliases[NistObjectIdentifiers.IdHMacWithSha3_512.Id] = "SHA3-512";
		Aliases["SHAKE128"] = "SHAKE128-256";
		Aliases[NistObjectIdentifiers.IdShake128.Id] = "SHAKE128-256";
		Aliases["SHAKE256"] = "SHAKE256-512";
		Aliases[NistObjectIdentifiers.IdShake256.Id] = "SHAKE256-512";

		Oids["SHA-224"] = NistObjectIdentifiers.IdSha224;
		Oids["SHA-256"] = NistObjectIdentifiers.IdSha256;
		Oids["SHA-384"] = NistObjectIdentifiers.IdSha384;
		Oids["SHA-512"] = NistObjectIdentifiers.IdSha512;
		Oids["SHA-512/224"] = NistObjectIdentifiers.IdSha512_224;
		Oids["SHA-512/256"] = NistObjectIdentifiers.IdSha512_256;
		Oids["SHA3-224"] = NistObjectIdentifiers.IdSha3_224;
		Oids["SHA3-256"] = NistObjectIdentifiers.IdSha3_256;
	}

	public static IDigest GetDigest(string algorithm)
	{
		if (algorithm == null)
			throw new ArgumentNullException(nameof(algorithm));

		string mechanism = CollectionUtilities.GetValueOrKey(Aliases, algorithm).ToUpperInvariant();

		try
		{
			DigestAlgorithm digestAlgorithm = Enums.GetEnumValue<DigestAlgorithm>(mechanism);

			switch (digestAlgorithm)
			{
				case DigestAlgorithm.SHA_256: return new Sha256Digest();
			}
		}
		catch (ArgumentException)
		{
		}

		throw new SecurityUtilityException("Digest " + mechanism + " not recognised.");
	}
}
