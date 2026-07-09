namespace Picket.Sources;

/// <summary>
/// Configures Gitea user repository source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="userName">The Gitea user name.</param>
/// <param name="credential">The credential used for Gitea API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference used for every repository.</param>
/// <param name="includeIssues">A value indicating whether Gitea issue bodies and comments should be scanned.</param>
/// <param name="issueState">The Gitea issue state filter.</param>
/// <param name="includeReleases">A value indicating whether Gitea release notes and assets should be scanned.</param>
/// <param name="includeActionArtifacts">A value indicating whether Gitea Actions artifact ZIP contents should be scanned.</param>
/// <param name="actionRunId">An optional Gitea Actions run ID whose artifacts should be scanned in each repository.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested artifact archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of artifact archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum artifact archive expansion ratio, or 0 for no cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GiteaUserSourceOptions(
    Uri endpoint,
    string userName,
    string credential,
    string gitRef = "",
    bool includeIssues = false,
    string issueState = GiteaSourceOptions.DefaultIssueState,
    bool includeReleases = false,
    bool includeActionArtifacts = false,
    int actionRunId = 0,
    long? maxFileBytes = null,
    int maxArchiveDepth = ArchiveScanDefaults.DefaultMaxDepth,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
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
    /// Gets the Gitea user name.
    /// </summary>
    public string UserName { get; } = GiteaOrganizationSourceOptions.NormalizeAccountName(userName, nameof(userName), "Gitea user must be a name, not a path.");

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
    /// Gets a value indicating whether Gitea Actions artifact ZIP contents should be scanned.
    /// </summary>
    public bool IncludeActionArtifacts { get; } = includeActionArtifacts;

    /// <summary>
    /// Gets the optional Gitea Actions run ID whose artifacts should be scanned.
    /// </summary>
    public int ActionRunId { get; } = RequireActionRunId(actionRunId, includeActionArtifacts);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GiteaSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested artifact archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of artifact archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum artifact archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

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
            includeReleases: IncludeReleases,
            includeActionArtifacts: IncludeActionArtifacts,
            actionRunId: ActionRunId,
            maxArchiveDepth: MaxArchiveDepth,
            maxArchiveEntries: MaxArchiveEntries,
            maxArchiveBytes: MaxArchiveBytes,
            maxArchiveCompressionRatio: MaxArchiveCompressionRatio);
    }

    private static int RequireActionRunId(int value, bool includeActionArtifacts)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value != 0 && !includeActionArtifacts)
        {
            throw new ArgumentException("Gitea Actions run ID requires Actions artifact enumeration.", nameof(value));
        }

        return value;
    }
}
