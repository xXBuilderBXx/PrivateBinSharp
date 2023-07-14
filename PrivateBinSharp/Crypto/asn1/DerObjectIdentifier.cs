using PrivateBinSharp.Crypto.math;
using PrivateBinSharp.Crypto.util;
using System.Text;

namespace PrivateBinSharp.Crypto.asn1;

internal class DerObjectIdentifier
	: Asn1Object
{
	internal class Meta : Asn1UniversalType
	{
		internal static readonly Asn1UniversalType Instance = new Meta();

		private Meta() : base(typeof(DerObjectIdentifier), Asn1Tags.ObjectIdentifier) { }

		internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
		{
			return CreatePrimitive(octetString.GetOctets(), false);
		}
	}

	public static DerObjectIdentifier FromContents(byte[] contents)
	{
		return CreatePrimitive(contents, true);
	}

	/**
         * return an OID from the passed in object
         *
         * @exception ArgumentException if the object cannot be converted.
         */
	public static DerObjectIdentifier GetInstance(object obj)
	{
		if (obj == null)
			return null;

		if (obj is DerObjectIdentifier derObjectIdentifier)
			return derObjectIdentifier;

		if (obj is IAsn1Convertible asn1Convertible)
		{
			Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
			if (asn1Object is DerObjectIdentifier converted)
				return converted;
		}
		else if (obj is byte[] bytes)
		{
			try
			{
				return (DerObjectIdentifier)Meta.Instance.FromByteArray(bytes);
			}
			catch (IOException e)
			{
				throw new ArgumentException("failed to construct object identifier from byte[]: " + e.Message);
			}
		}

		throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
	}

	public static DerObjectIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
	{
		/*
             * TODO[asn1] This block here is for backward compatibility, but should eventually be removed.
             * 
             * - see https://github.com/bcgit/bc-java/issues/1015
             */
		if (!declaredExplicit && !taggedObject.IsParsed())
		{
			Asn1Object baseObject = taggedObject.GetObject();
			if (!(baseObject is DerObjectIdentifier))
				return FromContents(Asn1OctetString.GetInstance(baseObject).GetOctets());
		}

		return (DerObjectIdentifier)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
	}

	private const long LongLimit = (long.MaxValue >> 7) - 0x7F;

	private static readonly DerObjectIdentifier[] Cache = new DerObjectIdentifier[1024];

	private readonly string identifier;
	private byte[] contents;

	public DerObjectIdentifier(string identifier)
	{
		if (identifier == null)
			throw new ArgumentNullException("identifier");
		if (!IsValidIdentifier(identifier))
			throw new FormatException("string " + identifier + " not an OID");

		this.identifier = identifier;
	}

	private DerObjectIdentifier(DerObjectIdentifier oid, string branchID)
	{
		if (!Asn1RelativeOid.IsValidIdentifier(branchID, 0))
			throw new ArgumentException("string " + branchID + " not a valid OID branch", "branchID");

		identifier = oid.Id + "." + branchID;
	}

	private DerObjectIdentifier(byte[] contents, bool clone)
	{
		identifier = ParseContents(contents);
		this.contents = clone ? Arrays.Clone(contents) : contents;
	}

	public virtual DerObjectIdentifier Branch(string branchID)
	{
		return new DerObjectIdentifier(this, branchID);
	}

	public string Id
	{
		get { return identifier; }
	}

	/**
         * Return  true if this oid is an extension of the passed in branch, stem.
         * @param stem the arc or branch that is a possible parent.
         * @return  true if the branch is on the passed in stem, false otherwise.
         */
	public virtual bool On(DerObjectIdentifier stem)
	{
		string id = Id, stemId = stem.Id;
		return id.Length > stemId.Length && id[stemId.Length] == '.' && Platform.StartsWith(id, stemId);
	}

	public override string ToString()
	{
		return identifier;
	}

	protected override bool Asn1Equals(Asn1Object asn1Object)
	{
		DerObjectIdentifier? that = asn1Object as DerObjectIdentifier;
		return null != that
			&& identifier == that.identifier;
	}

	protected override int Asn1GetHashCode()
	{
		return identifier.GetHashCode();
	}

	internal override IAsn1Encoding GetEncoding(int encoding)
	{
		return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.ObjectIdentifier, GetContents());
	}

	internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
	{
		return new PrimitiveEncoding(tagClass, tagNo, GetContents());
	}

	internal sealed override DerEncoding GetEncodingDer()
	{
		return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.ObjectIdentifier, GetContents());
	}

	internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
	{
		return new PrimitiveDerEncoding(tagClass, tagNo, GetContents());
	}

	private void DoOutput(MemoryStream bOut)
	{
		OidTokenizer tok = new OidTokenizer(identifier);

		string token = tok.NextToken();
		int first = int.Parse(token) * 40;

		token = tok.NextToken();
		if (token.Length <= 18)
		{
			Asn1RelativeOid.WriteField(bOut, first + long.Parse(token));
		}
		else
		{
			Asn1RelativeOid.WriteField(bOut, new BigInteger(token).Add(BigInteger.ValueOf(first)));
		}

		while (tok.HasMoreTokens)
		{
			token = tok.NextToken();
			if (token.Length <= 18)
			{
				Asn1RelativeOid.WriteField(bOut, long.Parse(token));
			}
			else
			{
				Asn1RelativeOid.WriteField(bOut, new BigInteger(token));
			}
		}
	}

	private byte[] GetContents()
	{
		lock (this)
		{
			if (contents == null)
			{
				MemoryStream bOut = new MemoryStream();
				DoOutput(bOut);
				contents = bOut.ToArray();
			}

			return contents;
		}
	}

	internal static DerObjectIdentifier CreatePrimitive(byte[] contents, bool clone)
	{
		int index = Arrays.GetHashCode(contents);

		index ^= index >> 20;
		index ^= index >> 10;
		index &= 1023;

		var originalEntry = Volatile.Read(ref Cache[index]);
		if (originalEntry != null && Arrays.AreEqual(contents, originalEntry.GetContents()))
			return originalEntry;

		var newEntry = new DerObjectIdentifier(contents, clone);

		var exchangedEntry = Interlocked.CompareExchange(ref Cache[index], newEntry, originalEntry);
		if (exchangedEntry != originalEntry)
		{
			if (exchangedEntry != null && Arrays.AreEqual(contents, exchangedEntry.GetContents()))
				return exchangedEntry;
		}

		return newEntry;
	}

	private static bool IsValidIdentifier(string identifier)
	{
		if (identifier.Length < 3 || identifier[1] != '.')
			return false;

		char first = identifier[0];
		if (first < '0' || first > '2')
			return false;

		return Asn1RelativeOid.IsValidIdentifier(identifier, 2);
	}

	private static string ParseContents(byte[] contents)
	{
		StringBuilder objId = new StringBuilder();
		long value = 0;
		BigInteger? bigValue = null;
		bool first = true;

		for (int i = 0; i != contents.Length; i++)
		{
			int b = contents[i];

			if (value <= LongLimit)
			{
				value += b & 0x7F;
				if ((b & 0x80) == 0)
				{
					if (first)
					{
						if (value < 40)
						{
							objId.Append('0');
						}
						else if (value < 80)
						{
							objId.Append('1');
							value -= 40;
						}
						else
						{
							objId.Append('2');
							value -= 80;
						}
						first = false;
					}

					objId.Append('.');
					objId.Append(value);
					value = 0;
				}
				else
				{
					value <<= 7;
				}
			}
			else
			{
				if (bigValue == null)
				{
					bigValue = BigInteger.ValueOf(value);
				}
				bigValue = bigValue.Or(BigInteger.ValueOf(b & 0x7F));
				if ((b & 0x80) == 0)
				{
					if (first)
					{
						objId.Append('2');
						bigValue = bigValue.Subtract(BigInteger.ValueOf(80));
						first = false;
					}

					objId.Append('.');
					objId.Append(bigValue);
					bigValue = null;
					value = 0;
				}
				else
				{
					bigValue = bigValue.ShiftLeft(7);
				}
			}
		}

		return objId.ToString();
	}
}
