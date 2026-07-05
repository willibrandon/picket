namespace Picket.Report;

/// <summary>
/// Represents the non-secret fields needed to triage a report finding.
/// </summary>
/// <param name="ruleId">The rule identifier associated with the finding.</param>
/// <param name="path">The reported path for the finding.</param>
/// <param name="line">The one-based start line for the finding, or zero when unavailable.</param>
/// <param name="fingerprint">The stable fingerprint associated with the finding, or an empty string when unavailable.</param>
public sealed class ReportFindingSummary(string ruleId, string path, int line, string fingerprint)
{
    /// <summary>
    /// Gets the rule identifier associated with the finding.
    /// </summary>
    public string RuleId { get; } = ruleId ?? throw new ArgumentNullException(nameof(ruleId));

    /// <summary>
    /// Gets the reported path for the finding.
    /// </summary>
    public string Path { get; } = path ?? throw new ArgumentNullException(nameof(path));

    /// <summary>
    /// Gets the one-based start line for the finding, or zero when unavailable.
    /// </summary>
    public int Line { get; } = ValidateLine(line);

    /// <summary>
    /// Gets the stable fingerprint associated with the finding, or an empty string when unavailable.
    /// </summary>
    public string Fingerprint { get; } = fingerprint ?? throw new ArgumentNullException(nameof(fingerprint));

    private static int ValidateLine(int line)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(line);
        return line;
    }
}
