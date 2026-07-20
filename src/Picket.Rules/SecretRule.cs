namespace Picket.Rules;

/// <summary>
/// Describes a byte-oriented secret detection rule.
/// </summary>
/// <param name="id">The stable rule identifier.</param>
/// <param name="description">The user-facing rule description.</param>
/// <param name="pattern">The content regex pattern in the compatibility dialect. Empty means path-only.</param>
/// <param name="secretGroup">The capture group that contains the secret. Zero means the whole match.</param>
/// <param name="entropy">The minimum Shannon entropy required for the secret. Zero disables entropy filtering.</param>
/// <param name="pathPattern">The optional path regex pattern in the compatibility dialect.</param>
/// <param name="allowlists">Per-rule allowlists used to suppress findings.</param>
/// <param name="keywords">Case-insensitive keywords used for candidate prefiltering.</param>
/// <param name="tags">Rule classification tags.</param>
/// <param name="skipReport">A value indicating whether normal findings for this rule are suppressed.</param>
/// <param name="requiredRules">Supporting rules required before a primary finding is reported.</param>
/// <param name="severity">The native severity value for reports and triage.</param>
/// <param name="confidence">The native confidence value for reports and triage.</param>
/// <param name="rulePack">The native rule pack that supplied the rule.</param>
/// <param name="provider">The owning provider or credential family.</param>
/// <param name="documentationUrl">The rule documentation or remediation URL.</param>
/// <param name="validation">Stable validation template identifiers supported by the rule.</param>
/// <param name="revocation">Stable revocation template identifiers supported by the rule.</param>
/// <param name="deprecated">A value indicating whether the rule is deprecated.</param>
/// <param name="examples">Positive examples that must produce findings for this rule during rule QA.</param>
/// <param name="negativeExamples">Negative examples that must not produce findings for this rule during rule QA.</param>
/// <param name="randomnessThreshold">The minimum native randomness score required for a finding. Zero disables score filtering.</param>
/// <param name="detector">The optional built-in structured detector name.</param>
public sealed class SecretRule(
    string id,
    string description,
    string pattern,
    int secretGroup = 0,
    double entropy = 0,
    string pathPattern = "",
    IReadOnlyList<SecretAllowlist>? allowlists = null,
    IReadOnlyList<string>? keywords = null,
    IReadOnlyList<string>? tags = null,
    bool skipReport = false,
    IReadOnlyList<SecretRequiredRule>? requiredRules = null,
    string severity = "",
    string confidence = "",
    string rulePack = "",
    string provider = "",
    string documentationUrl = "",
    IReadOnlyList<string>? validation = null,
    IReadOnlyList<string>? revocation = null,
    bool deprecated = false,
    IReadOnlyList<string>? examples = null,
    IReadOnlyList<string>? negativeExamples = null,
    double randomnessThreshold = 0,
    string detector = "")
{
    /// <summary>
    /// Gets the stable rule identifier.
    /// </summary>
    public string Id { get; } = RequireText(id);

    /// <summary>
    /// Gets the user-facing rule description.
    /// </summary>
    public string Description { get; } = description ?? string.Empty;

    /// <summary>
    /// Gets the content regex pattern in the compatibility dialect. Empty means path-only.
    /// </summary>
    public string Pattern { get; } = pattern ?? string.Empty;

    /// <summary>
    /// Gets the capture group that contains the secret. Zero means the whole match.
    /// </summary>
    public int SecretGroup { get; } = RequireNonNegative(secretGroup);

    /// <summary>
    /// Gets the minimum Shannon entropy required for the secret. Zero disables entropy filtering.
    /// </summary>
    public double Entropy { get; } = RequireNonNegativeFinite(entropy);

    /// <summary>
    /// Gets the optional path regex pattern in the compatibility dialect.
    /// </summary>
    public string PathPattern { get; } = RequirePatternOrPath(pattern, pathPattern);

    /// <summary>
    /// Gets per-rule allowlists used to suppress findings.
    /// </summary>
    public IReadOnlyList<SecretAllowlist> Allowlists { get; } = allowlists ?? [];

    /// <summary>
    /// Gets case-insensitive keywords used for candidate prefiltering.
    /// </summary>
    public IReadOnlyList<string> Keywords { get; } = keywords ?? [];

    /// <summary>
    /// Gets rule classification tags.
    /// </summary>
    public IReadOnlyList<string> Tags { get; } = tags ?? [];

    /// <summary>
    /// Gets a value indicating whether normal findings for this rule are suppressed.
    /// </summary>
    public bool SkipReport { get; } = skipReport;

    /// <summary>
    /// Gets supporting rules required before a primary finding is reported.
    /// </summary>
    public IReadOnlyList<SecretRequiredRule> RequiredRules { get; } = requiredRules ?? [];

    /// <summary>
    /// Gets the native severity value for reports and triage.
    /// </summary>
    public string Severity { get; } = string.IsNullOrWhiteSpace(severity) ? "critical" : severity;

    /// <summary>
    /// Gets the native confidence value for reports and triage.
    /// </summary>
    public string Confidence { get; } = string.IsNullOrWhiteSpace(confidence) ? "high" : confidence;

    /// <summary>
    /// Gets the native rule pack that supplied the rule.
    /// </summary>
    public string RulePack { get; } = rulePack ?? string.Empty;

    /// <summary>
    /// Gets the owning provider or credential family.
    /// </summary>
    public string Provider { get; } = provider ?? string.Empty;

    /// <summary>
    /// Gets the rule documentation or remediation URL.
    /// </summary>
    public string DocumentationUrl { get; } = documentationUrl ?? string.Empty;

    /// <summary>
    /// Gets stable validation template identifiers supported by the rule.
    /// </summary>
    public IReadOnlyList<string> Validation { get; } = validation ?? [];

    /// <summary>
    /// Gets stable revocation template identifiers supported by the rule.
    /// </summary>
    public IReadOnlyList<string> Revocation { get; } = revocation ?? [];

    /// <summary>
    /// Gets a value indicating whether the rule is deprecated.
    /// </summary>
    public bool Deprecated { get; } = deprecated;

    /// <summary>
    /// Gets positive examples that must produce findings for this rule during rule QA.
    /// </summary>
    public IReadOnlyList<string> Examples { get; } = examples ?? [];

    /// <summary>
    /// Gets negative examples that must not produce findings for this rule during rule QA.
    /// </summary>
    public IReadOnlyList<string> NegativeExamples { get; } = negativeExamples ?? [];

    /// <summary>
    /// Gets the minimum native randomness score required for a finding. Zero disables score filtering.
    /// </summary>
    public double RandomnessThreshold { get; } = RequireProbability(randomnessThreshold);

    /// <summary>
    /// Gets the optional built-in structured detector name.
    /// </summary>
    public string Detector { get; } = RequireDetector(detector);

    /// <summary>
    /// Creates a rule and normalizes optional collection arguments.
    /// </summary>
    /// <param name="id">The stable rule identifier.</param>
    /// <param name="description">The user-facing rule description.</param>
    /// <param name="pattern">The content regex pattern in the compatibility dialect. Empty means path-only.</param>
    /// <param name="secretGroup">The capture group that contains the secret. Zero means the whole match.</param>
    /// <param name="entropy">The minimum Shannon entropy required for the secret. Zero disables entropy filtering.</param>
    /// <param name="pathPattern">The optional path regex pattern in the compatibility dialect.</param>
    /// <param name="allowlists">Per-rule allowlists used to suppress findings.</param>
    /// <param name="keywords">Case-insensitive keywords used for candidate prefiltering.</param>
    /// <param name="tags">Rule classification tags.</param>
    /// <param name="skipReport">A value indicating whether normal findings for this rule are suppressed.</param>
    /// <param name="requiredRules">Supporting rules required before a primary finding is reported.</param>
    /// <param name="severity">The native severity value for reports and triage.</param>
    /// <param name="confidence">The native confidence value for reports and triage.</param>
    /// <param name="rulePack">The native rule pack that supplied the rule.</param>
    /// <param name="provider">The owning provider or credential family.</param>
    /// <param name="documentationUrl">The rule documentation or remediation URL.</param>
    /// <param name="validation">Stable validation template identifiers supported by the rule.</param>
    /// <param name="revocation">Stable revocation template identifiers supported by the rule.</param>
    /// <param name="deprecated">A value indicating whether the rule is deprecated.</param>
    /// <param name="examples">Positive examples that must produce findings for this rule during rule QA.</param>
    /// <param name="negativeExamples">Negative examples that must not produce findings for this rule during rule QA.</param>
    /// <param name="randomnessThreshold">The minimum native randomness score required for a finding. Zero disables score filtering.</param>
    /// <param name="detector">The optional built-in structured detector name.</param>
    /// <returns>The created rule.</returns>
    public static SecretRule Create(
        string id,
        string description,
        string pattern,
        int secretGroup = 0,
        double entropy = 0,
        string pathPattern = "",
        IReadOnlyList<SecretAllowlist>? allowlists = null,
        IReadOnlyList<string>? keywords = null,
        IReadOnlyList<string>? tags = null,
        bool skipReport = false,
        IReadOnlyList<SecretRequiredRule>? requiredRules = null,
        string severity = "",
        string confidence = "",
        string rulePack = "",
        string provider = "",
        string documentationUrl = "",
        IReadOnlyList<string>? validation = null,
        IReadOnlyList<string>? revocation = null,
        bool deprecated = false,
        IReadOnlyList<string>? examples = null,
        IReadOnlyList<string>? negativeExamples = null,
        double randomnessThreshold = 0,
        string detector = "")
    {
        return new SecretRule(
            id,
            description,
            pattern,
            secretGroup,
            entropy,
            pathPattern,
            allowlists ?? [],
            keywords ?? [],
            tags ?? [],
            skipReport,
            requiredRules ?? [],
            severity,
            confidence,
            rulePack,
            provider,
            documentationUrl,
            validation ?? [],
            revocation ?? [],
            deprecated,
            examples ?? [],
            negativeExamples ?? [],
            randomnessThreshold,
            detector);
    }

    private static string RequireText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static string RequirePatternOrPath(string? pattern, string? pathPattern)
    {
        string normalizedPathPattern = pathPattern ?? string.Empty;
        if (string.IsNullOrWhiteSpace(pattern) && string.IsNullOrWhiteSpace(normalizedPathPattern))
        {
            throw new ArgumentException("A rule requires a content regex or path regex.", nameof(pattern));
        }

        return normalizedPathPattern;
    }

    private static int RequireNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static double RequireNonNegativeFinite(double value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (!double.IsFinite(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Value must be finite.");
        }

        return value;
    }

    private static double RequireProbability(double value)
    {
        RequireNonNegativeFinite(value);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 1);
        return value;
    }

    private static string RequireDetector(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 0 && !PicketBuiltInDetectorNames.IsKnown(value))
        {
            throw new ArgumentException($"Unknown built-in detector '{value}'.", nameof(value));
        }

        return value;
    }
}
