using PrivateBinSharp.Crypto.util.date;

namespace PrivateBinSharp.Crypto.util
{
    internal static class Enums
    {
        internal static TEnum GetEnumValue<TEnum>(string s)
            where TEnum : struct, Enum
        {
            // We only want to parse single named constants
            if (s.Length > 0 && char.IsLetter(s[0]) && s.IndexOf(',') < 0)
            {
                s = s.Replace('-', '_');
                s = s.Replace('/', '_');

                return Enum.Parse<TEnum>(s, false);
            }

            throw new ArgumentException();
        }

        internal static TEnum[] GetEnumValues<TEnum>()
            where TEnum : struct, Enum
        {
            return Enum.GetValues<TEnum>();
        }

        internal static TEnum GetArbitraryValue<TEnum>()
            where TEnum : struct, Enum
        {
            TEnum[] values = GetEnumValues<TEnum>();
            int pos = (int)(DateTimeUtilities.CurrentUnixMs() & int.MaxValue) % values.Length;
            return values[pos];
        }
    }
}
