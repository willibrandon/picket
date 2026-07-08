namespace Picket.Sources;

/// <summary>
/// Configures GitHub repository source enumeration.
/// </summary>
/// <param name="endpoint">The GitHub REST API endpoint.</param>
/// <param name="repository">The repository selector in owner/name form, or a GitHub repository URL.</param>
/// <param name="credential">The credential used for GitHub API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="pullRequestNumber">An optional pull request number whose head should be scanned.</param>
/// <param name="includeIssues">A value indicating whether GitHub issue bodies and comments should be scanned.</param>
/// <param name="issueState">The issue state filter to scan.</param>
/// <param name="includeReleases">A value indicating whether GitHub release bodies and release assets should be scanned.</param>
/// <param name="includeActionArtifacts">A value indicating whether GitHub Actions artifact ZIP contents should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested artifact archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of artifact archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum artifact archive expansion ratio, or 0 for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when an artifact entry path should be scanned.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitHubSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string gitRef = "",
    int pullRequestNumber = 0,
    bool includeIssues = false,
    string issueState = GitHubSourceOptions.DefaultIssueState,
    bool includeReleases = false,
    bool includeActionArtifacts = false,
    long? maxFileBytes = null,
    int maxArchiveDepth = ArchiveScanDefaults.DefaultMaxDepth,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;

    /// <summary>
    /// Gets the default GitHub issue state filter.
    /// </summary>
    public const string DefaultIssueState = "all";

    private readonly string _credential = RequireCredential(credential);
    private readonly (string Owner, string Name) _repository = ParseRepository(repository);

    /// <summary>
    /// Gets the normalized GitHub REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the repository owner or organization.
    /// </summary>
    public string Owner => _repository.Owner;

    /// <summary>
    /// Gets the repository name.
    /// </summary>
    public string RepositoryName => _repository.Name;

    /// <summary>
    /// Gets the repository selector in owner/name form.
    /// </summary>
    public string Repository => string.Concat(_repository.Owner, "/", _repository.Name);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeRef(gitRef, pullRequestNumber);

    /// <summary>
    /// Gets the optional pull request number whose head should be scanned.
    /// </summary>
    public int PullRequestNumber { get; } = RequirePullRequestNumber(pullRequestNumber);

    /// <summary>
    /// Gets a value indicating whether GitHub issue bodies and comments should be scanned.
    /// </summary>
    public bool IncludeIssues { get; } = RequireIncludeIssues(includeIssues, pullRequestNumber);

    /// <summary>
    /// Gets the issue state filter.
    /// </summary>
    public string IssueState { get; } = NormalizeIssueState(issueState);

    /// <summary>
    /// Gets a value indicating whether GitHub release bodies and release assets should be scanned.
    /// </summary>
    public bool IncludeReleases { get; } = RequireIncludeReleases(includeReleases, pullRequestNumber);

    /// <summary>
    /// Gets a value indicating whether GitHub Actions artifact ZIP contents should be scanned.
    /// </summary>
    public bool IncludeActionArtifacts { get; } = RequireIncludeActionArtifacts(includeActionArtifacts, pullRequestNumber);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested artifact archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of artifact archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum artifact archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the default public GitHub REST API endpoint.
    /// </summary>
    /// <returns>The normalized public GitHub REST API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://api.github.com/", UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("GitHub API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("GitHub API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    private static (string Owner, string Name) ParseRepository(string repository)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repository);
        string normalized = repository.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? repositoryUri))
        {
            string[] uriSegments = repositoryUri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (uriSegments.Length >= 2)
            {
                return ValidateRepositorySegments(
                    Uri.UnescapeDataString(uriSegments[0]),
                    StripGitSuffix(Uri.UnescapeDataString(uriSegments[1])));
            }
        }

        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length != 2)
        {
            throw new ArgumentException("GitHub repository must be in owner/name form or be an absolute repository URL.", nameof(repository));
        }

        return ValidateRepositorySegments(segments[0], StripGitSuffix(segments[1]));
    }

    private static (string Owner, string Name) ValidateRepositorySegments(string owner, string name)
    {
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("GitHub repository owner and name must not be empty.");
        }

        return (owner.Trim(), name.Trim());
    }

    private static string StripGitSuffix(string value)
    {
        return value.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value;
    }

    internal static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    internal static string NormalizeOptionalText(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
    }

    private static string NormalizeRef(string value, int pullRequestNumber)
    {
        string normalized = NormalizeOptionalText(value);
        if (pullRequestNumber != 0 && normalized.Length != 0)
        {
            throw new ArgumentException("GitHub source options accept either a ref or a pull request number, not both.", nameof(value));
        }

        return normalized;
    }

    internal static long RequireMaxFileBytes(long? value, string parameterName)
    {
        if (!value.HasValue)
        {
            return DefaultMaxFileBytes;
        }

        if (value.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value.Value, "Remote download byte caps must be greater than zero.");
        }

        return value.Value;
    }

    private static int RequirePullRequestNumber(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static bool RequireIncludeIssues(bool value, int pullRequestNumber)
    {
        if (value && pullRequestNumber != 0)
        {
            throw new ArgumentException("GitHub source options accept either issue enumeration or a pull request number, not both.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeReleases(bool value, int pullRequestNumber)
    {
        if (value && pullRequestNumber != 0)
        {
            throw new ArgumentException("GitHub source options accept either release enumeration or a pull request number, not both.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeActionArtifacts(bool value, int pullRequestNumber)
    {
        if (value && pullRequestNumber != 0)
        {
            throw new ArgumentException("GitHub source options accept either Actions artifact enumeration or a pull request number, not both.", nameof(value));
        }

        return value;
    }

    private static int RequireMaxArchiveDepth(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static int RequireMaxArchiveEntries(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static long? RequireMaxArchiveBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    private static int RequireMaxArchiveCompressionRatio(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    /// <summary>
    /// Normalizes and validates a GitHub issue state filter.
    /// </summary>
    /// <param name="value">The issue state filter value.</param>
    /// <returns>The normalized issue state filter.</returns>
    /// <exception cref="ArgumentException"><paramref name="value" /> is not a supported GitHub issue state filter.</exception>
    public static string NormalizeIssueState(string value)
    {
        string normalized = NormalizeOptionalText(value).ToLowerInvariant();
        if (normalized.Length == 0)
        {
            return DefaultIssueState;
        }

        if (normalized is "open" or "closed" or "all")
        {
            return normalized;
        }

        throw new ArgumentException("GitHub issue state must be one of: open, closed, all.", nameof(value));
    }
}
