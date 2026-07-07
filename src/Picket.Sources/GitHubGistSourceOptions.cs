namespace Picket.Sources;

/// <summary>
/// Configures GitHub gist source enumeration.
/// </summary>
/// <param name="endpoint">The GitHub REST API endpoint.</param>
/// <param name="credential">The credential used for GitHub API requests.</param>
/// <param name="gistId">An optional single gist identifier to scan.</param>
/// <param name="includeAuthenticatedGists">A value indicating whether the authenticated user's gists should be scanned.</param>
/// <param name="userName">An optional GitHub user login whose public gists should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitHubGistSourceOptions(
    Uri endpoint,
    string credential,
    string gistId = "",
    bool includeAuthenticatedGists = false,
    string userName = "",
    long? maxFileBytes = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private readonly string _credential = GitHubSourceOptions.RequireCredential(credential);

    /// <summary>
    /// Gets the normalized GitHub REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = GitHubSourceOptions.NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the optional single gist identifier to scan.
    /// </summary>
    public string GistId { get; } = NormalizeGistId(gistId);

    /// <summary>
    /// Gets a value indicating whether the authenticated user's gists should be scanned.
    /// </summary>
    public bool IncludeAuthenticatedGists { get; } = includeAuthenticatedGists;

    /// <summary>
    /// Gets the optional GitHub user login whose public gists should be scanned.
    /// </summary>
    public string UserName { get; } = NormalizeUserName(userName);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GitHubSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Validates that exactly one gist source selector is configured.
    /// </summary>
    /// <exception cref="ArgumentException">The configured gist source selector set is ambiguous or empty.</exception>
    public void ValidateSelector()
    {
        int selectors = 0;
        if (GistId.Length != 0)
        {
            selectors++;
        }

        if (IncludeAuthenticatedGists)
        {
            selectors++;
        }

        if (UserName.Length != 0)
        {
            selectors++;
        }

        if (selectors != 1)
        {
            throw new ArgumentException("GitHub gist source options require exactly one of a gist ID, authenticated gist enumeration, or user gist enumeration.");
        }
    }

    private static string NormalizeGistId(string value)
    {
        string normalized = GitHubSourceOptions.NormalizeOptionalText(value);
        if (normalized.Contains('/', StringComparison.Ordinal)
            || normalized.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException("GitHub gist ID must not contain path separators.", nameof(value));
        }

        return normalized;
    }

    private static string NormalizeUserName(string value)
    {
        string normalized = GitHubSourceOptions.NormalizeOptionalText(value);
        if (normalized.Contains('/', StringComparison.Ordinal)
            || normalized.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException("GitHub gist user must be a login, not a path.", nameof(value));
        }

        return normalized;
    }
}
