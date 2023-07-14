using System.Globalization;

namespace PrivateBinSharp.Crypto.util;

internal static class Platform
{
	private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

	internal static bool EqualsIgnoreCase(string a, string b)
	{
		return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
	}

	internal static string GetEnvironmentVariable(string variable)
	{
		try
		{
			return Environment.GetEnvironmentVariable(variable);
		}
		catch (System.Security.SecurityException)
		{
			// We don't have the required permission to read this environment variable,
			// which is fine, just act as if it's not set
			return null;
		}
	}

	internal static int IndexOf(string source, char value, int startIndex)
	{
		return InvariantCompareInfo.IndexOf(source, value, startIndex, CompareOptions.Ordinal);
	}

	internal static bool Is64BitProcess
	{
		get { return Environment.Is64BitProcess; }
	}

	internal static bool StartsWith(string source, string prefix)
	{
		return InvariantCompareInfo.IsPrefix(source, prefix, CompareOptions.Ordinal);
	}

	internal static bool EndsWith(string source, string suffix)
	{
		return InvariantCompareInfo.IsSuffix(source, suffix, CompareOptions.Ordinal);
	}

	internal static string GetTypeName(object obj)
	{
		return GetTypeName(obj.GetType());
	}

	internal static string GetTypeName(Type t)
	{
		return t.FullName;
	}
}
