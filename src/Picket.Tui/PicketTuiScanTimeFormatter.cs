using System.Globalization;

namespace Picket.Tui;

/// <summary>
/// Formats scan timestamps and elapsed durations for scanner-console views and yanks.
/// </summary>
internal static class PicketTuiScanTimeFormatter
{
    /// <summary>
    /// Formats the current timing state of a scan workspace.
    /// </summary>
    /// <param name="scan">The scan workspace to describe.</param>
    /// <returns>A display-ready timing description.</returns>
    internal static string Format(PicketTuiScanWorkspace scan)
    {
        if (!scan.LastStartedAt.HasValue)
        {
            return "Not run yet";
        }

        if (!scan.LastCompletedAt.HasValue)
        {
            return string.Concat(
                "Started ",
                FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()),
                ", still running");
        }

        return string.Concat(
            "Started ",
            FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()),
            ", completed ",
            FormatTimestamp(scan.LastCompletedAt.GetValueOrDefault()),
            ", elapsed ",
            FormatElapsed(scan.LastElapsed.GetValueOrDefault()));
    }

    /// <summary>
    /// Formats scan timing for constrained terminal chrome.
    /// </summary>
    /// <param name="scan">The scan workspace to describe.</param>
    /// <returns>A compact display-ready timing description.</returns>
    internal static string FormatCompact(PicketTuiScanWorkspace scan)
    {
        if (!scan.LastStartedAt.HasValue)
        {
            return "Not run yet";
        }

        if (!scan.LastCompletedAt.HasValue)
        {
            return string.Concat("Started ", FormatLocalClock(scan.LastStartedAt.GetValueOrDefault()));
        }

        return string.Concat(
            "Completed ",
            FormatLocalClock(scan.LastCompletedAt.GetValueOrDefault()),
            " | ",
            FormatElapsed(scan.LastElapsed.GetValueOrDefault()));
    }

    private static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
    }

    private static string FormatLocalClock(DateTimeOffset value)
    {
        return value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
    }

    private static string FormatElapsed(TimeSpan value)
    {
        return value.TotalSeconds < 1
            ? string.Create(CultureInfo.InvariantCulture, $"{value.TotalMilliseconds:0} ms")
            : string.Create(CultureInfo.InvariantCulture, $"{value.TotalSeconds:0.0} s");
    }
}
