using System.Text;

namespace PrivateBinSharp.Crypto.util
{
    /// <summary> General string utilities.</summary>
    public static class Strings
    {
        public static string FromByteArray(byte[] bs)
        {
            return string.Create(bs.Length, bs, (chars, bytes) =>
            {
                for (int i = 0; i < chars.Length; ++i)
                {
                    chars[i] = Convert.ToChar(bytes[i]);
                }
            });
        }

        public static byte[] ToByteArray(char[] cs)
        {
            byte[] bs = new byte[cs.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(cs[i]);
            }
            return bs;
        }

        public static byte[] ToByteArray(string s)
        {
            byte[] bs = new byte[s.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(s[i]);
            }
            return bs;
        }

        public static byte[] ToByteArray(ReadOnlySpan<char> cs)
        {
            byte[] bs = new byte[cs.Length];
            for (int i = 0; i < bs.Length; ++i)
            {
                bs[i] = Convert.ToByte(cs[i]);
            }
            return bs;
        }


        public static string FromAsciiByteArray(byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes);
        }


        public static byte[] ToAsciiByteArray(string s)
        {
            return Encoding.ASCII.GetBytes(s);
        }

        public static string FromUtf8ByteArray(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        public static byte[] ToUtf8ByteArray(char[] cs)
        {
            return Encoding.UTF8.GetBytes(cs);
        }

        public static byte[] ToUtf8ByteArray(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] ToUtf8ByteArray(ReadOnlySpan<char> cs)
        {
            int count = Encoding.UTF8.GetByteCount(cs);
            byte[] bytes = new byte[count];
            Encoding.UTF8.GetBytes(cs, bytes);
            return bytes;
        }
    }
}
