using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;


namespace PrivateBinSharp.Crypto.util
{
    internal static class Pack
    {
        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bs.AsSpan(off), n);
        }

        internal static uint BE_To_UInt32(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt32BigEndian(bs.AsSpan(off));
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt64BigEndian(bs.AsSpan(off), n);
        }

        internal static ulong BE_To_UInt64(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt64BigEndian(bs.AsSpan(off));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint BE_To_UInt32(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt32BigEndian(bs);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void BE_To_UInt32(ReadOnlySpan<byte> bs, Span<uint> ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = BE_To_UInt32(bs);
                bs = bs[4..];
            }
        }

        internal static uint BE_To_UInt32_Low(ReadOnlySpan<byte> bs)
        {
            int len = bs.Length;
            Debug.Assert(1 <= len && len <= 4);

            uint result = bs[0];
            for (int i = 1; i < len; ++i)
            {
                result <<= 8;
                result |= bs[i];
            }
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong BE_To_UInt64(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt64BigEndian(bs);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint LE_To_UInt32(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(bs);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint LE_To_UInt32(ReadOnlySpan<byte> bs, int off)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(bs[off..]);
        }

        internal static uint LE_To_UInt32_Low(ReadOnlySpan<byte> bs)
        {
            int len = bs.Length;
            Debug.Assert(1 <= len && len <= 4);

            uint result = bs[0];
            int pos = 0;
            for (int i = 1; i < len; ++i)
            {
                pos += 8;
                result |= (uint)bs[i] << pos;
            }
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_BE(uint n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bs, n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_LE(uint n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bs, n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_BE(ulong n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt64BigEndian(bs, n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_LE(ulong n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bs, n);
        }
    }
}
