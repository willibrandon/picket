namespace Picket.Report;

/// <summary>
/// Represents the non-secret fields needed to triage a report finding.
/// </summary>
/// <param name="ruleId">The rule identifier associated with the finding.</param>
/// <param name="path">The reported path for the finding.</param>
/// <param name="line">The one-based start line for the finding, or zero when unavailable.</param>
/// <param name="fingerprint">The stable fingerprint associated with the finding, or an empty string when unavailable.</param>
/// <param name="startColumn">The one-based start column for the finding, or zero when unavailable.</param>
/// <param name="randomnessScore">The native randomness score, or <see langword="null" /> when unavailable.</param>
/// <param name="randomnessClassification">The native randomness classification, or an empty string when unavailable.</param>
/// <param name="randomnessModel">The native randomness model identifier, or an empty string when unavailable.</param>
public sealed class ReportFindingSummary(
    string ruleId,
    string path,
    int line,
    string fingerprint,
    int startColumn = 0,
    double? randomnessScore = null,
    string randomnessClassification = "",
    string randomnessModel = "")
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
    public int Line { get; } = ValidateNonNegative(line);

    /// <summary>
    /// Gets the one-based start column for the finding, or zero when unavailable.
    /// </summary>
    public int StartColumn { get; } = ValidateNonNegative(startColumn);

    /// <summary>
    /// Gets the stable fingerprint associated with the finding, or an empty string when unavailable.
    /// </summary>
    public string Fingerprint { get; } = fingerprint ?? throw new ArgumentNullException(nameof(fingerprint));

    /// <summary>
    /// Gets the native randomness score, or <see langword="null" /> when unavailable.
    /// </summary>
    public double? RandomnessScore { get; } = ValidateScore(randomnessScore);

    /// <summary>
    /// Gets the native randomness classification, or an empty string when unavailable.
    /// </summary>
    public string RandomnessClassification { get; } = randomnessClassification ?? throw new ArgumentNullException(nameof(randomnessClassification));

    /// <summary>
    /// Gets the native randomness model identifier, or an empty string when unavailable.
    /// </summary>
    public string RandomnessModel { get; } = randomnessModel ?? throw new ArgumentNullException(nameof(randomnessModel));

    private static int ValidateNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static double? ValidateScore(double? value)
    {
        if (value.HasValue && (!double.IsFinite(value.Value) || value.Value < 0 || value.Value > 1))
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Value must be finite and between zero and one.");
        }

        return value;
    }
}
