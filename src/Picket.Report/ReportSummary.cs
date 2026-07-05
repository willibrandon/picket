namespace Picket.Report;

/// <summary>
/// Represents a non-secret summary of a secrets report.
/// </summary>
/// <param name="format">The detected report format.</param>
/// <param name="findings">The non-secret finding summaries.</param>
public sealed class ReportSummary(string format, IReadOnlyList<ReportFindingSummary> findings)
{
    private readonly IReadOnlyList<ReportFindingSummary> _findings = findings ?? throw new ArgumentNullException(nameof(findings));

    /// <summary>
    /// Gets the detected report format.
    /// </summary>
    public string Format { get; } = ValidateFormat(format);

    /// <summary>
    /// Gets the non-secret finding summaries.
    /// </summary>
    public IReadOnlyList<ReportFindingSummary> Findings => _findings;

    /// <summary>
    /// Gets the number of findings in the report.
    /// </summary>
    public int FindingCount => _findings.Count;

    /// <summary>
    /// Gets the number of distinct reported files in the report.
    /// </summary>
    public int FileCount => CountDistinctPaths(_findings);

    private static string ValidateFormat(string format)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(format);
        return format;
    }

    private static int CountDistinctPaths(IReadOnlyList<ReportFindingSummary> findings)
    {
        var paths = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < findings.Count; i++)
        {
            if (findings[i].Path.Length != 0)
            {
                paths.Add(findings[i].Path);
            }
        }

        return paths.Count;
    }
}
