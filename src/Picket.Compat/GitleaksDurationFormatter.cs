using System.Globalization;

namespace Picket.Compat;

/// <summary>
/// Formats elapsed durations using the rounding and display contract used by Gitleaks.
/// </summary>
internal static class GitleaksDurationFormatter
{
    private const long InitialScaleTicks = 100 * TimeSpan.TicksPerSecond;
    private const long TicksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1_000;

    /// <summary>
    /// Formats an elapsed duration using three significant decimal positions and Go duration units.
    /// </summary>
    /// <param name="duration">The non-negative duration to format.</param>
    /// <returns>The formatted duration.</returns>
    internal static string Format(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duration));
        }

        long scaleTicks = InitialScaleTicks;
        while (scaleTicks > duration.Ticks && scaleTicks > 1)
        {
            scaleTicks /= 10;
        }

        long quantumTicks = Math.Max(scaleTicks / 100, 1);
        long roundedTicks = RoundTicks(duration.Ticks, quantumTicks);
        return FormatRoundedTicks(roundedTicks);
    }

    private static string FormatDecimal(long ticks, long ticksPerUnit, string suffix)
    {
        decimal value = (decimal)ticks / ticksPerUnit;
        return string.Concat(value.ToString("0.#######", CultureInfo.InvariantCulture), suffix);
    }

    private static string FormatRoundedTicks(long ticks)
    {
        if (ticks == 0)
        {
            return "0s";
        }

        if (ticks < TicksPerMicrosecond)
        {
            return string.Concat(
                (ticks * 100).ToString(CultureInfo.InvariantCulture),
                "ns");
        }

        if (ticks < TimeSpan.TicksPerMillisecond)
        {
            return FormatDecimal(ticks, TicksPerMicrosecond, "µs");
        }

        if (ticks < TimeSpan.TicksPerSecond)
        {
            return FormatDecimal(ticks, TimeSpan.TicksPerMillisecond, "ms");
        }

        long hours = ticks / TimeSpan.TicksPerHour;
        ticks %= TimeSpan.TicksPerHour;
        long minutes = ticks / TimeSpan.TicksPerMinute;
        ticks %= TimeSpan.TicksPerMinute;
        string seconds = FormatDecimal(ticks, TimeSpan.TicksPerSecond, "s");

        if (hours != 0)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{hours}h{minutes}m{seconds}");
        }

        return minutes != 0
            ? string.Create(CultureInfo.InvariantCulture, $"{minutes}m{seconds}")
            : seconds;
    }

    private static long RoundTicks(long ticks, long quantumTicks)
    {
        long quotient = ticks / quantumTicks;
        long remainder = ticks % quantumTicks;
        if (remainder * 2 >= quantumTicks)
        {
            quotient++;
        }

        return quotient * quantumTicks;
    }
}
