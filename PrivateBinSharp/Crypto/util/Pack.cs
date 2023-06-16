using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;


namespace PrivateBinSharp.Crypto.util
{
    internal static class Pack
    {
        internal static void UInt16_To_BE(ushort n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bs.AsSpan(off), n);
        }

        internal static void UInt16_To_BE(ushort[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                UInt16_To_BE(ns[nsOff + i], bs, bsOff);
                bsOff += 2;
            }
        }

        internal static byte[] UInt16_To_BE(ushort[] ns, int nsOff, int nsLen)
        {
            byte[] bs = new byte[2 * nsLen];
            UInt16_To_BE(ns, nsOff, nsLen, bs, 0);
            return bs;
        }

        internal static ushort BE_To_UInt16(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt16BigEndian(bs.AsSpan(off));
        }

        internal static void BE_To_UInt16(byte[] bs, int bsOff, ushort[] ns, int nsOff)
        {
            ns[nsOff] = BE_To_UInt16(bs, bsOff);
        }

        internal static ushort[] BE_To_UInt16(byte[] bs, int off, int len)
        {
            if ((len & 1) != 0)
                throw new ArgumentException("must be a multiple of 2", "len");

            ushort[] ns = new ushort[len / 2];
            for (int i = 0; i < len; i += 2)
            {
                BE_To_UInt16(bs, off + i, ns, i >> 1);
            }
            return ns;
        }

        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bs.AsSpan(off), n);
        }

        internal static void UInt32_To_BE_High(uint n, byte[] bs, int off, int len)
        {
            Debug.Assert(1 <= len && len <= 4);

            int pos = 24;
            bs[off] = (byte)(n >> pos);
            for (int i = 1; i < len; ++i)
            {
                pos -= 8;
                bs[off + i] = (byte)(n >> pos);
            }
        }

        internal static void UInt32_To_BE(uint[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt32_To_BE(ns[i], bs, off);
                off += 4;
            }
        }

        internal static uint BE_To_UInt32(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt32BigEndian(bs.AsSpan(off));
        }

        internal static uint BE_To_UInt32_Low(byte[] bs, int off, int len)
        {
            Debug.Assert(1 <= len && len <= 4);

            uint result = bs[off];
            for (int i = 1; i < len; ++i)
            {
                result <<= 8;
                result |= bs[off + i];
            }
            return result;
        }

        internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt64BigEndian(bs.AsSpan(off), n);
        }

        internal static void UInt64_To_BE_High(ulong n, byte[] bs, int off, int len)
        {
            Debug.Assert(1 <= len && len <= 8);

            int pos = 56;
            bs[off] = (byte)(n >> pos);
            for (int i = 1; i < len; ++i)
            {
                pos -= 8;
                bs[off + i] = (byte)(n >> pos);
            }
        }

        internal static void UInt64_To_BE(ulong[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt64_To_BE(ns[i], bs, off);
                off += 8;
            }
        }

        internal static ulong BE_To_UInt64(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt64BigEndian(bs.AsSpan(off));
        }

        internal static void UInt16_To_LE(ushort n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bs.AsSpan(off), n);
        }

        internal static void UInt16_To_LE(ushort[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt16_To_LE(ns[i], bs, off);
                off += 2;
            }
        }

        internal static ushort LE_To_UInt16(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(off));
        }

        internal static void LE_To_UInt16(byte[] bs, int off, ushort[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt16(bs, off);
                off += 2;
            }
        }

        internal static uint LE_To_UInt32(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(off));
        }

        internal static void LE_To_UInt32(byte[] bs, int off, uint[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt32(bs, off);
                off += 4;
            }
        }

        internal static void UInt64_To_LE(ulong n, byte[] bs, int off)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bs.AsSpan(off), n);
        }

        internal static void UInt64_To_LE_Low(ulong n, byte[] bs, int off, int len)
        {
            Debug.Assert(1 <= len && len <= 8);

            bs[off] = (byte)n;
            for (int i = 1; i < len; ++i)
            {
                n >>= 8;
                bs[off + i] = (byte)n;
            }
        }

        internal static ulong LE_To_UInt64(byte[] bs, int off)
        {
            return BinaryPrimitives.ReadUInt64LittleEndian(bs.AsSpan(off));
        }

        internal static void LE_To_UInt64(byte[] bs, int off, ulong[] ns)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                ns[i] = LE_To_UInt64(bs, off);
                off += 8;
            }
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
        internal static ushort LE_To_UInt16(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(bs);
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
        internal static ulong LE_To_UInt64(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt64LittleEndian(bs);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt16_To_BE(ushort n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bs, n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt16_To_LE(ushort n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bs, n);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_BE(uint n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bs, n);
        }

        internal static void UInt32_To_BE_High(uint n, Span<byte> bs)
        {
            int len = bs.Length;
            Debug.Assert(1 <= len && len <= 4);

            int pos = 24;
            bs[0] = (byte)(n >> pos);
            for (int i = 1; i < len; ++i)
            {
                pos -= 8;
                bs[i] = (byte)(n >> pos);
            }
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

        internal static void UInt64_To_BE_High(ulong n, Span<byte> bs)
        {
            int len = bs.Length;
            Debug.Assert(1 <= len && len <= 8);

            int pos = 56;
            bs[0] = (byte)(n >> pos);
            for (int i = 1; i < len; ++i)
            {
                pos -= 8;
                bs[i] = (byte)(n >> pos);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_LE(ulong n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bs, n);
        }
    }
}
