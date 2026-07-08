namespace Picket.Sources;

/// <summary>
/// Configures Gitea organization repository source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="organization">The Gitea organization name.</param>
/// <param name="credential">The credential used for Gitea API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference used for every repository.</param>
/// <param name="includeIssues">A value indicating whether Gitea issue bodies and comments should be scanned.</param>
/// <param name="issueState">The Gitea issue state filter.</param>
/// <param name="includeReleases">A value indicating whether Gitea release notes and assets should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GiteaOrganizationSourceOptions(
    Uri endpoint,
    string organization,
    string credential,
    string gitRef = "",
    bool includeIssues = false,
    string issueState = GiteaSourceOptions.DefaultIssueState,
    bool includeReleases = false,
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private readonly string _credential = GiteaSourceOptions.RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Gitea REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = GiteaSourceOptions.RequireCredentialTransport(
        GiteaSourceOptions.NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the Gitea organization name.
    /// </summary>
    public string Organization { get; } = NormalizeAccountName(organization, nameof(organization), "Gitea organization must be a name, not an owner/name path.");

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = GiteaSourceOptions.NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets a value indicating whether Gitea issue bodies and comments should be scanned.
    /// </summary>
    public bool IncludeIssues { get; } = includeIssues;

    /// <summary>
    /// Gets the Gitea issue state filter.
    /// </summary>
    public string IssueState { get; } = GiteaSourceOptions.NormalizeIssueState(issueState);

    /// <summary>
    /// Gets a value indicating whether Gitea release notes and assets should be scanned.
    /// </summary>
    public bool IncludeReleases { get; } = includeReleases;

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GiteaSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    internal GiteaSourceOptions CreateRepositoryOptions(string repository, string gitRef)
    {
        return new GiteaSourceOptions(
            Endpoint,
            repository,
            Credential,
            gitRef,
            IncludeIssues,
            IssueState,
            maxFileBytes: MaxFileBytes,
            allowInsecureCredentialTransport: AllowInsecureCredentialTransport,
            isPathAllowed: IsPathAllowed,
            warningSink: WarningSink,
            isCancellationRequested: IsCancellationRequested,
            includeReleases: IncludeReleases);
    }

    internal static string NormalizeAccountName(string value, string parameterName, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        string normalized = value.Trim();
        if (normalized.Contains('/', StringComparison.Ordinal)
            || normalized.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException(message, parameterName);
        }

        return normalized;
    }
}
