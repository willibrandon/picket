namespace Picket.Rules;

/// <summary>
/// Describes a byte-oriented secret detection rule.
/// </summary>
/// <param name="id">The stable rule identifier.</param>
/// <param name="description">The user-facing rule description.</param>
/// <param name="pattern">The regex pattern in the compatibility dialect.</param>
/// <param name="secretGroup">The capture group that contains the secret. Zero means the whole match.</param>
/// <param name="keywords">Case-insensitive keywords used for candidate prefiltering.</param>
/// <param name="tags">Rule classification tags.</param>
public sealed class SecretRule(
    string id,
    string description,
    string pattern,
    int secretGroup = 0,
    IReadOnlyList<string>? keywords = null,
    IReadOnlyList<string>? tags = null)
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
    /// Gets the regex pattern in the compatibility dialect.
    /// </summary>
    public string Pattern { get; } = RequireText(pattern);

    /// <summary>
    /// Gets the capture group that contains the secret. Zero means the whole match.
    /// </summary>
    public int SecretGroup { get; } = RequireNonNegative(secretGroup);

    /// <summary>
    /// Gets case-insensitive keywords used for candidate prefiltering.
    /// </summary>
    public IReadOnlyList<string> Keywords { get; } = keywords ?? [];

    /// <summary>
    /// Gets rule classification tags.
    /// </summary>
    public IReadOnlyList<string> Tags { get; } = tags ?? [];

    /// <summary>
    /// Creates a rule and normalizes optional collection arguments.
    /// </summary>
    /// <param name="id">The stable rule identifier.</param>
    /// <param name="description">The user-facing rule description.</param>
    /// <param name="pattern">The regex pattern in the compatibility dialect.</param>
    /// <param name="secretGroup">The capture group that contains the secret. Zero means the whole match.</param>
    /// <param name="keywords">Case-insensitive keywords used for candidate prefiltering.</param>
    /// <param name="tags">Rule classification tags.</param>
    /// <returns>The created rule.</returns>
    public static SecretRule Create(
        string id,
        string description,
        string pattern,
        int secretGroup = 0,
        IReadOnlyList<string>? keywords = null,
        IReadOnlyList<string>? tags = null)
    {
        return new SecretRule(
            id,
            description,
            pattern,
            secretGroup,
            keywords ?? [],
            tags ?? []);
    }

    private static string RequireText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int RequireNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }
}
