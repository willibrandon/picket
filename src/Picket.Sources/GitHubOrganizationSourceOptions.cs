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
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for no cap.</param>
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
    long? maxFileBytes = null,
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
    /// Gets the maximum file content bytes to download, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxFileBytes { get; } = GitHubSourceOptions.RequireMaxFileBytes(maxFileBytes);

    internal string Credential => _credential;

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
}
