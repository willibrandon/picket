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

    internal long StartTimestamp { get; }

    internal bool Verbose { get; set; }
}
