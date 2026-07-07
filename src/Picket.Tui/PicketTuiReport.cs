using Picket.Report;

namespace Picket.Tui;

/// <summary>
/// Represents a report loaded into the terminal UI.
/// </summary>
/// <param name="path">The resolved report path.</param>
/// <param name="summary">The non-secret report summary.</param>
/// <param name="loadedAt">The time the report was loaded.</param>
internal sealed class PicketTuiReport(string path, ReportSummary summary, DateTimeOffset loadedAt)
{
    /// <summary>
    /// Gets the resolved report path.
    /// </summary>
    internal string Path { get; } = path;

    /// <summary>
    /// Gets the non-secret report summary.
    /// </summary>
    internal ReportSummary Summary { get; } = summary;

    /// <summary>
    /// Gets the time the report was loaded.
    /// </summary>
    internal DateTimeOffset LoadedAt { get; } = loadedAt;
}
