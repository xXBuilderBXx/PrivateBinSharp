//using Org.BouncyCastle.Asn1.Cms;
//using Org.BouncyCastle.Asn1.CryptoPro;
//using Org.BouncyCastle.Asn1.Kisa;
//using Org.BouncyCastle.Asn1.Misc;
//using Org.BouncyCastle.Asn1.Nsri;
//using Org.BouncyCastle.Asn1.Ntt;
//using Org.BouncyCastle.Asn1.Oiw;
//using Org.BouncyCastle.Asn1.Pkcs;
using PrivateBinSharp.Crypto.asn1.nist;
using PrivateBinSharp.Crypto.crypto.parameters;
using PrivateBinSharp.Crypto.util.collections;

namespace PrivateBinSharp.Crypto.security;

internal static class ParameterUtilities
{
	private static readonly IDictionary<string, string> Algorithms =
		new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
	private static readonly IDictionary<string, int> BasicIVSizes =
		new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

	static ParameterUtilities()
	{
		AddAlgorithm("AES",
			"AESWRAP");
		AddAlgorithm("AES128",
			"2.16.840.1.101.3.4.2",
			NistObjectIdentifiers.IdAes128Cbc,
			NistObjectIdentifiers.IdAes128Ccm,
			NistObjectIdentifiers.IdAes128Cfb,
			NistObjectIdentifiers.IdAes128Ecb,
			NistObjectIdentifiers.IdAes128Gcm,
			NistObjectIdentifiers.IdAes128Ofb,
			NistObjectIdentifiers.IdAes128Wrap);
		AddAlgorithm("AES192",
			"2.16.840.1.101.3.4.22",
			NistObjectIdentifiers.IdAes192Cbc,
			NistObjectIdentifiers.IdAes192Ccm,
			NistObjectIdentifiers.IdAes192Cfb,
			NistObjectIdentifiers.IdAes192Ecb,
			NistObjectIdentifiers.IdAes192Gcm,
			NistObjectIdentifiers.IdAes192Ofb,
			NistObjectIdentifiers.IdAes192Wrap);
		AddAlgorithm("AES256",
			"2.16.840.1.101.3.4.42",
			NistObjectIdentifiers.IdAes256Cbc,
			NistObjectIdentifiers.IdAes256Ccm,
			NistObjectIdentifiers.IdAes256Cfb,
			NistObjectIdentifiers.IdAes256Ecb,
			NistObjectIdentifiers.IdAes256Gcm,
			NistObjectIdentifiers.IdAes256Ofb,
			NistObjectIdentifiers.IdAes256Wrap);
		AddAlgorithm("ARIA");

		AddAlgorithm("BLOWFISH",
			"1.3.6.1.4.1.3029.1.2");
		AddAlgorithm("CAMELLIA",
			"CAMELLIAWRAP");

		AddAlgorithm("CAST5",
			"1.2.840.113533.7.66.10");
		AddAlgorithm("CAST6");
		AddAlgorithm("CHACHA");

		AddAlgorithm("HC128");
		AddAlgorithm("HC256");
		AddAlgorithm("IDEA",
			"1.3.6.1.4.1.188.7.1.1.2");
		AddAlgorithm("NOEKEON");

		AddAlgorithm("RC4",
			"ARC4",
			"1.2.840.113549.3.4");
		AddAlgorithm("RC5",
			"RC5-32");
		AddAlgorithm("RC5-64");
		AddAlgorithm("RC6");
		AddAlgorithm("RIJNDAEL");
		AddAlgorithm("SALSA20");

		AddAlgorithm("SERPENT");
		AddAlgorithm("SKIPJACK");
		AddAlgorithm("SM4");
		AddAlgorithm("TEA");
		AddAlgorithm("THREEFISH-256");
		AddAlgorithm("THREEFISH-512");
		AddAlgorithm("THREEFISH-1024");
		AddAlgorithm("TNEPRES");
		AddAlgorithm("TWOFISH");
		AddAlgorithm("VMPC");
		AddAlgorithm("VMPC-KSA3");
		AddAlgorithm("XTEA");

		AddBasicIVSizeEntries(8, "BLOWFISH", "CHACHA", "DES", "DESEDE", "DESEDE3", "SALSA20");
		AddBasicIVSizeEntries(12, "CHACHA7539");
		AddBasicIVSizeEntries(16, "AES", "AES128", "AES192", "AES256", "ARIA", "ARIA128", "ARIA192", "ARIA256",
			"CAMELLIA", "CAMELLIA128", "CAMELLIA192", "CAMELLIA256", "NOEKEON", "SEED", "SM4");
	}

	private static void AddAlgorithm(string canonicalName, params object[] aliases)
	{
		Algorithms[canonicalName] = canonicalName;

		foreach (object alias in aliases)
		{
			Algorithms[alias.ToString()] = canonicalName;
		}
	}

	private static void AddBasicIVSizeEntries(int size, params string[] algorithms)
	{
		foreach (string algorithm in algorithms)
		{
			BasicIVSizes.Add(algorithm, size);
		}
	}

	public static string GetCanonicalAlgorithmName(string algorithm)
	{
		return CollectionUtilities.GetValueOrNull(Algorithms, algorithm);
	}

	public static KeyParameter CreateKeyParameter(
		string algorithm,
		byte[] keyBytes,
		int offset,
		int length)
	{
		if (algorithm == null)
			throw new ArgumentNullException(nameof(algorithm));

		string canonical = GetCanonicalAlgorithmName(algorithm);

		if (canonical == null)
			throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");
		return new KeyParameter(keyBytes, offset, length);
	}
}
