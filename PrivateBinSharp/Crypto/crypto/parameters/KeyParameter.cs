using PrivateBinSharp.Crypto.util;
using System.Buffers;

namespace PrivateBinSharp.Crypto.crypto.parameters;

internal class KeyParameter
	: ICipherParameters
{
	public static KeyParameter Create<TState>(int length, TState state, SpanAction<byte, TState> action)
	{
		if (action == null)
			throw new ArgumentNullException(nameof(action));
		if (length < 1)
			throw new ArgumentOutOfRangeException(nameof(length));

		KeyParameter result = new KeyParameter(length);
		action(result.m_key, state);
		return result;
	}

	private readonly byte[] m_key;

	public KeyParameter(byte[] key)
	{
		if (key == null)
			throw new ArgumentNullException(nameof(key));

		m_key = (byte[])key.Clone();
	}

	public KeyParameter(byte[] key, int keyOff, int keyLen)
	{
		if (key == null)
			throw new ArgumentNullException(nameof(key));
		if (keyOff < 0 || keyOff > key.Length)
			throw new ArgumentOutOfRangeException(nameof(keyOff));
		if (keyLen < 0 || keyLen > key.Length - keyOff)
			throw new ArgumentOutOfRangeException(nameof(keyLen));

		m_key = new byte[keyLen];
		Array.Copy(key, keyOff, m_key, 0, keyLen);
	}

	public KeyParameter(ReadOnlySpan<byte> key)
	{
		m_key = key.ToArray();
	}

	private KeyParameter(int length)
	{
		if (length < 1)
			throw new ArgumentOutOfRangeException(nameof(length));

		m_key = new byte[length];
	}

	public void CopyTo(byte[] buf, int off, int len)
	{
		if (m_key.Length != len)
			throw new ArgumentOutOfRangeException(nameof(len));

		Array.Copy(m_key, 0, buf, off, len);
	}

	public byte[] GetKey()
	{
		return (byte[])m_key.Clone();
	}

	public int KeyLength => m_key.Length;

	internal bool FixedTimeEquals(byte[] data)
	{
		return Arrays.FixedTimeEquals(m_key, data);
	}

	internal ReadOnlySpan<byte> Key => m_key;

	public KeyParameter Reverse()
	{
		var reversed = new KeyParameter(m_key.Length);
		Arrays.Reverse(m_key, reversed.m_key);
		return reversed;
	}
}
