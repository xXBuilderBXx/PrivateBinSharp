using PrivateBinSharp.Crypto.util;

namespace PrivateBinSharp.Crypto.asn1;

/**
* Class representing the DER-type External
*/
internal class DerExternal
	: Asn1Object
{
	internal class Meta : Asn1UniversalType
	{
		internal static readonly Asn1UniversalType Instance = new Meta();

		private Meta() : base(typeof(DerExternal), Asn1Tags.External) { }

		internal override Asn1Object FromImplicitConstructed(Asn1Sequence sequence)
		{
			return sequence.ToAsn1External();
		}
	}

	public static DerExternal? GetInstance(object obj)
	{
		if (obj == null)
			return null;

		if (obj is DerExternal derExternal)
			return derExternal;

		if (obj is IAsn1Convertible asn1Convertible)
		{
			Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
			if (asn1Object is DerExternal converted)
				return converted;
		}
		else if (obj is byte[] bytes)
		{
			try
			{
				return (DerExternal)Meta.Instance.FromByteArray(bytes);
			}
			catch (IOException e)
			{
				throw new ArgumentException("failed to construct external from byte[]: " + e.Message);
			}
		}

		throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
	}

	public static DerExternal GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
	{
		return (DerExternal)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
	}

	internal readonly DerObjectIdentifier directReference;
	internal readonly DerInteger indirectReference;
	internal readonly Asn1ObjectDescriptor dataValueDescriptor;
	internal readonly int encoding;
	internal readonly Asn1Object externalContent;

	public DerExternal(Asn1EncodableVector vector)
		: this(new BerSequence(vector))
	{
	}

	public DerExternal(Asn1Sequence sequence)
	{
		int offset = 0;

		Asn1Object asn1 = GetObjFromSequence(sequence, offset);
		if (asn1 is DerObjectIdentifier)
		{
			directReference = (DerObjectIdentifier)asn1;
			asn1 = GetObjFromSequence(sequence, ++offset);
		}
		if (asn1 is DerInteger)
		{
			indirectReference = (DerInteger)asn1;
			asn1 = GetObjFromSequence(sequence, ++offset);
		}
		if (!(asn1 is Asn1TaggedObject))
		{
			dataValueDescriptor = (Asn1ObjectDescriptor)asn1;
			asn1 = GetObjFromSequence(sequence, ++offset);
		}

		if (sequence.Count != offset + 1)
			throw new ArgumentException("input sequence too large", "sequence");

		if (!(asn1 is Asn1TaggedObject))
			throw new ArgumentException(
				"No tagged object found in sequence. Structure doesn't seem to be of type External", "sequence");

		Asn1TaggedObject obj = (Asn1TaggedObject)asn1;
		encoding = CheckEncoding(obj.TagNo);
		externalContent = GetExternalContent(obj);
	}

	/**
	* Creates a new instance of DerExternal
	* See X.690 for more informations about the meaning of these parameters
	* @param directReference The direct reference or <code>null</code> if not set.
	* @param indirectReference The indirect reference or <code>null</code> if not set.
	* @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
	* @param externalData The external data in its encoded form.
	*/
	[Obsolete("Pass 'externalData' at type Asn1TaggedObject")]
	public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
		Asn1ObjectDescriptor dataValueDescriptor, DerTaggedObject externalData)
		: this(directReference, indirectReference, dataValueDescriptor, (Asn1TaggedObject)externalData)
	{
	}

	public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
		Asn1ObjectDescriptor dataValueDescriptor, Asn1TaggedObject externalData)
	{
		this.directReference = directReference;
		this.indirectReference = indirectReference;
		this.dataValueDescriptor = dataValueDescriptor;
		encoding = CheckEncoding(externalData.TagNo);
		externalContent = GetExternalContent(externalData);
	}

	/**
	* Creates a new instance of DerExternal.
	* See X.690 for more informations about the meaning of these parameters
	* @param directReference The direct reference or <code>null</code> if not set.
	* @param indirectReference The indirect reference or <code>null</code> if not set.
	* @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
	* @param encoding The encoding to be used for the external data
	* @param externalData The external data
	*/
	public DerExternal(DerObjectIdentifier directReference, DerInteger indirectReference,
		Asn1ObjectDescriptor dataValueDescriptor, int encoding, Asn1Object externalData)
	{
		this.directReference = directReference;
		this.indirectReference = indirectReference;
		this.dataValueDescriptor = dataValueDescriptor;
		this.encoding = CheckEncoding(encoding);
		externalContent = CheckExternalContent(encoding, externalData);
	}

	internal virtual Asn1Sequence BuildSequence()
	{
		Asn1EncodableVector v = new Asn1EncodableVector(4);
		v.AddOptional(directReference, indirectReference, dataValueDescriptor);
		v.Add(new DerTaggedObject(0 == encoding, encoding, externalContent));
		return new DerSequence(v);
	}

	internal override IAsn1Encoding GetEncoding(int encoding)
	{
		return BuildSequence().GetEncodingImplicit(Asn1OutputStream.EncodingDer, Asn1Tags.Universal,
			Asn1Tags.External);
	}

	internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
	{
		return BuildSequence().GetEncodingImplicit(Asn1OutputStream.EncodingDer, tagClass, tagNo);
	}

	internal sealed override DerEncoding GetEncodingDer()
	{
		return BuildSequence().GetEncodingDerImplicit(Asn1Tags.Universal, Asn1Tags.External);
	}

	internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
	{
		return BuildSequence().GetEncodingDerImplicit(tagClass, tagNo);
	}

	protected override int Asn1GetHashCode()
	{
		return Objects.GetHashCode(directReference)
			^ Objects.GetHashCode(indirectReference)
			^ Objects.GetHashCode(dataValueDescriptor)
			^ encoding
			^ externalContent.GetHashCode();
	}

	protected override bool Asn1Equals(Asn1Object asn1Object)
	{
		DerExternal? that = asn1Object as DerExternal;
		return null != that
			&& Equals(directReference, that.directReference)
			&& Equals(indirectReference, that.indirectReference)
			&& Equals(dataValueDescriptor, that.dataValueDescriptor)
			&& encoding == that.encoding
			&& externalContent.Equals(that.externalContent);
	}

	public Asn1ObjectDescriptor DataValueDescriptor
	{
		get { return dataValueDescriptor; }
	}

	public DerObjectIdentifier DirectReference
	{
		get { return directReference; }
	}

	/**
	* The encoding of the content. Valid values are
	* <ul>
	* <li><code>0</code> single-ASN1-type</li>
	* <li><code>1</code> OCTET STRING</li>
	* <li><code>2</code> BIT STRING</li>
	* </ul>
	*/
	public int Encoding
	{
		get { return encoding; }
	}

	public Asn1Object ExternalContent
	{
		get { return externalContent; }
	}

	public DerInteger IndirectReference
	{
		get { return indirectReference; }
	}

	private static int CheckEncoding(int encoding)
	{
		if (encoding < 0 || encoding > 2)
			throw new InvalidOperationException("invalid encoding value: " + encoding);

		return encoding;
	}

	private static Asn1Object CheckExternalContent(int tagNo, Asn1Object externalContent)
	{
		switch (tagNo)
		{
			case 1:
				return Asn1OctetString.Meta.Instance.CheckedCast(externalContent);
			case 2:
				return DerBitString.Meta.Instance.CheckedCast(externalContent);
			default:
				return externalContent;
		}
	}

	private static Asn1Object GetExternalContent(Asn1TaggedObject encoding)
	{
		int tagClass = encoding.TagClass, tagNo = encoding.TagNo;
		if (Asn1Tags.ContextSpecific != tagClass)
			throw new ArgumentException("invalid tag: " + Asn1Utilities.GetTagText(tagClass, tagNo), "encoding");

		switch (tagNo)
		{
			case 0:
				return encoding.GetExplicitBaseObject().ToAsn1Object();
			case 1:
				return Asn1OctetString.GetInstance(encoding, false);
			case 2:
				return DerBitString.GetInstance(encoding, false);
			default:
				throw new ArgumentException("invalid tag: " + Asn1Utilities.GetTagText(tagClass, tagNo), "encoding");
		}
	}

	private static Asn1Object GetObjFromSequence(Asn1Sequence sequence, int index)
	{
		if (sequence.Count <= index)
			throw new ArgumentException("too few objects in input sequence", "sequence");

		return sequence[index].ToAsn1Object();
	}
}
