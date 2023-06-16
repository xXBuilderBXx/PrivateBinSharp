using System.Runtime.CompilerServices;

namespace PrivateBinSharp.Crypto.util
{
    internal static class Spans
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void CopyFrom<T>(this Span<T> output, ReadOnlySpan<T> input)
        {
            input[..output.Length].CopyTo(output);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Span<T> FromNullable<T>(T[]? array, int start)
        {
            return array == null ? Span<T>.Empty : array.AsSpan(start);
        }
    }
}
