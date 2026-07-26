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
/// <param name="severity">The finding severity, or an empty string when unavailable.</param>
/// <param name="confidence">The finding confidence, or an empty string when unavailable.</param>
/// <param name="validationState">The credential validation state, or an empty string when unavailable.</param>
/// <param name="commit">The source commit identifier, or an empty string when unavailable.</param>
/// <param name="author">The source commit author, or an empty string when unavailable.</param>
public sealed class ReportFindingSummary(
    string ruleId,
    string path,
    int line,
    string fingerprint,
    int startColumn = 0,
    double? randomnessScore = null,
    string randomnessClassification = "",
    string randomnessModel = "",
    string severity = "",
    string confidence = "",
    string validationState = "",
    string commit = "",
    string author = "")
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

    /// <summary>
    /// Gets the finding severity, or an empty string when unavailable.
    /// </summary>
    public string Severity { get; } = severity ?? throw new ArgumentNullException(nameof(severity));

    /// <summary>
    /// Gets the finding confidence, or an empty string when unavailable.
    /// </summary>
    public string Confidence { get; } = confidence ?? throw new ArgumentNullException(nameof(confidence));

    /// <summary>
    /// Gets the credential validation state, or an empty string when unavailable.
    /// </summary>
    public string ValidationState { get; } = validationState ?? throw new ArgumentNullException(nameof(validationState));

    /// <summary>
    /// Gets the source commit identifier, or an empty string when unavailable.
    /// </summary>
    public string Commit { get; } = commit ?? throw new ArgumentNullException(nameof(commit));

    /// <summary>
    /// Gets the source commit author, or an empty string when unavailable.
    /// </summary>
    public string Author { get; } = author ?? throw new ArgumentNullException(nameof(author));

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
