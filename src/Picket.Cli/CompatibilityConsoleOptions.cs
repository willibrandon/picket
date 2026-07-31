using System.Diagnostics;

namespace Picket;

internal sealed class CompatibilityConsoleOptions
{
    internal CompatibilityConsoleOptions()
    {
        StartTimestamp = Stopwatch.GetTimestamp();
    }

    internal CompatibilityLogLevel LogLevel { get; set; } = CompatibilityLogLevel.Info;

    internal CompatibilityScanMetrics Metrics { get; } = new();

    internal bool NoBanner { get; set; }

    internal bool NoColor { get; set; }

    internal long StartTimestamp { get; private set; }

    internal bool Verbose { get; set; }

    internal void RestartTiming()
    {
        StartTimestamp = Stopwatch.GetTimestamp();
    }
}
