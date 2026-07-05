namespace Picket.Rules;

/// <summary>
/// Describes Gitleaks-compatible allowlist checks for suppressing findings.
/// </summary>
/// <param name="description">The human-readable allowlist description.</param>
/// <param name="condition">The condition used to combine configured checks.</param>
/// <param name="commits">Commit SHA values that are allowed.</param>
/// <param name="pathPatterns">Path regex patterns that are allowed.</param>
/// <param name="regexTarget">The finding field tested by regex patterns.</param>
/// <param name="regexPatterns">Content regex patterns that are allowed.</param>
/// <param name="stopWords">Case-insensitive stopwords matched against the secret.</param>
public sealed class SecretAllowlist(
    string description = "",
    AllowlistCondition condition = AllowlistCondition.Or,
    IReadOnlyList<string>? commits = null,
    IReadOnlyList<string>? pathPatterns = null,
    AllowlistRegexTarget regexTarget = AllowlistRegexTarget.Secret,
    IReadOnlyList<string>? regexPatterns = null,
    IReadOnlyList<string>? stopWords = null)
{
    /// <summary>
    /// Gets the human-readable allowlist description.
    /// </summary>
    public string Description { get; } = description ?? string.Empty;

    /// <summary>
    /// Gets the condition used to combine configured checks.
    /// </summary>
    public AllowlistCondition Condition { get; } = condition;

    /// <summary>
    /// Gets commit SHA values that are allowed.
    /// </summary>
    public IReadOnlyList<string> Commits { get; } = NormalizeCommits(commits);

    /// <summary>
    /// Gets path regex patterns that are allowed.
    /// </summary>
    public IReadOnlyList<string> PathPatterns { get; } = pathPatterns ?? [];

    /// <summary>
    /// Gets the finding field tested by regex patterns.
    /// </summary>
    public AllowlistRegexTarget RegexTarget { get; } = regexTarget;

    /// <summary>
    /// Gets content regex patterns that are allowed.
    /// </summary>
    public IReadOnlyList<string> RegexPatterns { get; } = regexPatterns ?? [];

    /// <summary>
    /// Gets case-insensitive stopwords matched against the secret.
    /// </summary>
    public IReadOnlyList<string> StopWords { get; } = NormalizeStopWords(stopWords);

    /// <summary>
    /// Creates an allowlist and validates that it has at least one check.
    /// </summary>
    /// <param name="description">The human-readable allowlist description.</param>
    /// <param name="condition">The condition used to combine configured checks.</param>
    /// <param name="commits">Commit SHA values that are allowed.</param>
    /// <param name="pathPatterns">Path regex patterns that are allowed.</param>
    /// <param name="regexTarget">The finding field tested by regex patterns.</param>
    /// <param name="regexPatterns">Content regex patterns that are allowed.</param>
    /// <param name="stopWords">Case-insensitive stopwords matched against the secret.</param>
    /// <returns>The created allowlist.</returns>
    public static SecretAllowlist Create(
        string description = "",
        AllowlistCondition condition = AllowlistCondition.Or,
        IReadOnlyList<string>? commits = null,
        IReadOnlyList<string>? pathPatterns = null,
        AllowlistRegexTarget regexTarget = AllowlistRegexTarget.Secret,
        IReadOnlyList<string>? regexPatterns = null,
        IReadOnlyList<string>? stopWords = null)
    {
        var allowlist = new SecretAllowlist(
            description,
            condition,
            commits,
            pathPatterns,
            regexTarget,
            regexPatterns,
            stopWords);
        if (!allowlist.HasChecks)
        {
            throw new ArgumentException("Allowlist must contain at least one check.", nameof(commits));
        }

        return allowlist;
    }

    internal bool HasChecks =>
        Commits.Count != 0 ||
        PathPatterns.Count != 0 ||
        RegexPatterns.Count != 0 ||
        StopWords.Count != 0;

    private static IReadOnlyList<string> NormalizeCommits(IReadOnlyList<string>? commits)
    {
        if (commits is null || commits.Count == 0)
        {
            return [];
        }

        var normalized = new HashSet<string>(StringComparer.Ordinal);
        foreach (string commit in commits)
        {
            string value = commit.Trim().ToLowerInvariant();
            if (value.Length != 0)
            {
                normalized.Add(value);
            }
        }

        return [.. normalized];
    }

    private static IReadOnlyList<string> NormalizeStopWords(IReadOnlyList<string>? stopWords)
    {
        if (stopWords is null || stopWords.Count == 0)
        {
            return [];
        }

        var normalized = new HashSet<string>(StringComparer.Ordinal);
        foreach (string stopWord in stopWords)
        {
            string value = stopWord.ToLowerInvariant();
            if (value.Length != 0)
            {
                normalized.Add(value);
            }
        }

        return [.. normalized];
    }
}
