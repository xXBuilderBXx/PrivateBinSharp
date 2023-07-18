using System.Text;

namespace PrivateBinSharp.Crypto.util.collections;

internal abstract class CollectionUtilities
{

	public static T GetValueOrKey<T>(IDictionary<T, T> d, T k)
	{
		return d.TryGetValue(k, out var v) ? v : k;
	}

	public static V? GetValueOrNull<K, V>(IDictionary<K, V> d, K k)
		where V : class
	{
		return d.TryGetValue(k, out var v) ? v : null;
	}

	public static string ToString<T>(IEnumerable<T> c)
	{
		IEnumerator<T> e = c.GetEnumerator();
		if (!e.MoveNext())
			return "[]";

		StringBuilder sb = new StringBuilder("[");
		sb.Append(e.Current);
		while (e.MoveNext())
		{
			sb.Append(", ");
			sb.Append(e.Current);
		}
		sb.Append(']');
		return sb.ToString();
	}
}
