namespace PrivateBinSharp.Crypto.util.date;

internal static class DateTimeUtilities
{
	public static readonly DateTime UnixEpoch = DateTime.UnixEpoch;

	public static readonly long MaxUnixMs =
		(DateTime.MaxValue.Ticks - UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond;
	public static readonly long MinUnixMs = 0L;

	/// <summary>
	/// Return the number of milliseconds since the Unix epoch (1 Jan., 1970 UTC) for a given DateTime value.
	/// </summary>
	/// <remarks>The DateTime value will be converted to UTC (using <see cref="DateTime.ToUniversalTime"/> before
	/// conversion.</remarks>
	/// <param name="dateTime">A DateTime value not before the epoch.</param>
	/// <returns>Number of whole milliseconds after epoch.</returns>
	/// <exception cref="ArgumentOutOfRangeException">'dateTime' is before the epoch.</exception>
	public static long DateTimeToUnixMs(DateTime dateTime)
	{
		DateTime utc = dateTime.ToUniversalTime();
		if (utc.CompareTo(UnixEpoch) < 0)
			throw new ArgumentOutOfRangeException(nameof(dateTime), "DateTime value may not be before the epoch");

		return (utc.Ticks - UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond;
	}

	/// <summary>
	/// Return the current number of milliseconds since the Unix epoch (1 Jan., 1970 UTC).
	/// </summary>
	public static long CurrentUnixMs()
	{
		return DateTimeToUnixMs(DateTime.UtcNow);
	}

	public static DateTime WithPrecisionSecond(DateTime dateTime)
	{
		long ticks = dateTime.Ticks - dateTime.Ticks % TimeSpan.TicksPerSecond;
		return new DateTime(ticks, dateTime.Kind);
	}
}
