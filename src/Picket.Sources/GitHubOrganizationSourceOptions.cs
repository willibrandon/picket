namespace Picket.Sources;

/// <summary>
/// Configures GitHub organization repository source enumeration.
/// </summary>
/// <param name="endpoint">The GitHub REST API endpoint.</param>
/// <param name="organization">The GitHub organization login.</param>
/// <param name="credential">The credential used for GitHub API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference used for every repository.</param>
/// <param name="repositoryType">The organization repository type filter.</param>
/// <param name="includeIssues">A value indicating whether GitHub issue bodies and comments should be scanned.</param>
/// <param name="issueState">The issue state filter to scan.</param>
/// <param name="includeReleases">A value indicating whether GitHub release bodies and release assets should be scanned.</param>
/// <param name="includeActionArtifacts">A value indicating whether GitHub Actions artifact ZIP contents should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, <see langword="null" /> for the default cap, or 0 for no cap.</param>
/// <param name="maxArchiveDepth">The maximum nested artifact archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of artifact archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum artifact archive expansion ratio, or 0 for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when an artifact entry path should be scanned.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitHubOrganizationSourceOptions(
    Uri endpoint,
    string organization,
    string credential,
    string gitRef = "",
    string repositoryType = GitHubOrganizationSourceOptions.DefaultRepositoryType,
    bool includeIssues = false,
    string issueState = GitHubSourceOptions.DefaultIssueState,
    bool includeReleases = false,
    bool includeActionArtifacts = false,
    long? maxFileBytes = null,
    int maxArchiveDepth = 1,
    int maxArchiveEntries = 4096,
    long? maxArchiveBytes = 512_000_000,
    int maxArchiveCompressionRatio = 1000,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    /// <summary>
    /// Gets the default GitHub organization repository type filter.
    /// </summary>
    public const string DefaultRepositoryType = "all";

    private readonly string _credential = GitHubSourceOptions.RequireCredential(credential);

    /// <summary>
    /// Gets the normalized GitHub REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = GitHubSourceOptions.NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the GitHub organization login.
    /// </summary>
    public string Organization { get; } = NormalizeOrganization(organization);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = GitHubSourceOptions.NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets the organization repository type filter.
    /// </summary>
    public string RepositoryType { get; } = NormalizeRepositoryType(repositoryType);

    /// <summary>
    /// Gets a value indicating whether GitHub issue bodies and comments should be scanned.
    /// </summary>
    public bool IncludeIssues { get; } = includeIssues;

    /// <summary>
    /// Gets the issue state filter.
    /// </summary>
    public string IssueState { get; } = GitHubSourceOptions.NormalizeIssueState(issueState);

    /// <summary>
    /// Gets a value indicating whether GitHub release bodies and release assets should be scanned.
    /// </summary>
    public bool IncludeReleases { get; } = includeReleases;

    /// <summary>
    /// Gets a value indicating whether GitHub Actions artifact ZIP contents should be scanned.
    /// </summary>
    public bool IncludeActionArtifacts { get; } = includeActionArtifacts;

    /// <summary>
    /// Gets the maximum file content bytes to download, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxFileBytes { get; } = GitHubSourceOptions.RequireMaxFileBytes(maxFileBytes);

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

    private static string NormalizeOrganization(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim();
        if (normalized.Contains('/', StringComparison.Ordinal))
        {
            throw new ArgumentException("GitHub organization must be a login, not owner/name form.", nameof(value));
        }

        return normalized;
    }

    private static string NormalizeRepositoryType(string value)
    {
        string normalized = GitHubSourceOptions.NormalizeOptionalText(value);
        if (normalized.Length == 0)
        {
            return DefaultRepositoryType;
        }

        if (normalized is "all" or "public" or "private" or "forks" or "sources" or "member")
        {
            return normalized;
        }

        throw new ArgumentException("GitHub repository type must be one of: all, public, private, forks, sources, member.", nameof(value));
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
}
