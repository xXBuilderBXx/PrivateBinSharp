namespace PrivateBinSharp.Crypto.util.io;

internal abstract class BaseOutputStream
	: Stream
{
	public sealed override bool CanRead { get { return false; } }
	public sealed override bool CanSeek { get { return false; } }
	public sealed override bool CanWrite { get { return true; } }

	// TODO[api] sealed
	public override void CopyTo(Stream destination, int bufferSize) { throw new NotSupportedException(); }

	// TODO[api] sealed
	public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
	{
		throw new NotSupportedException();
	}

	public override void Flush() { }
	public sealed override long Length { get { throw new NotSupportedException(); } }
	public sealed override long Position
	{
		get { throw new NotSupportedException(); }
		set { throw new NotSupportedException(); }
	}
	public sealed override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
	public sealed override int Read(Span<byte> buffer) { throw new NotSupportedException(); }
	// TODO[api] sealed
	public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		throw new NotSupportedException();
	}

	// TODO[api] ReadByte
	public sealed override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
	public sealed override void SetLength(long value) { throw new NotSupportedException(); }

	public override void Write(byte[] buffer, int offset, int count)
	{
		Streams.ValidateBufferArguments(buffer, offset, count);

		for (int i = 0; i < count; ++i)
		{
			WriteByte(buffer[offset + i]);
		}
	}

	public override void Write(ReadOnlySpan<byte> buffer)
	{
		int count = buffer.Length;
		for (int i = 0; i < count; ++i)
		{
			WriteByte(buffer[i]);
		}
	}

	public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		return Streams.WriteAsync(this, buffer, cancellationToken);
	}

	public virtual void Write(params byte[] buffer)
	{
		Write(buffer, 0, buffer.Length);
	}
}
