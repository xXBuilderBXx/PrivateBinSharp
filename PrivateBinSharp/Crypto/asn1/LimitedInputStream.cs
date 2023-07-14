using PrivateBinSharp.Crypto.util.io;

namespace PrivateBinSharp.Crypto.asn1;

internal abstract class LimitedInputStream
	: BaseInputStream
{
	protected readonly Stream _in;
	private int _limit;

	internal LimitedInputStream(Stream inStream, int limit)
	{
		_in = inStream;
		_limit = limit;
	}

	internal virtual int Limit
	{
		get { return _limit; }
	}

	protected void SetParentEofDetect()
	{
		if (_in is IndefiniteLengthInputStream)
		{
			((IndefiniteLengthInputStream)_in).SetEofOn00(true);
		}
	}
}
