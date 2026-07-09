namespace Picket.Sources;

/// <summary>
/// Configures Bitbucket Cloud workspace repository source enumeration.
/// </summary>
/// <param name="endpoint">The Bitbucket Cloud REST API endpoint.</param>
/// <param name="workspace">The Bitbucket workspace whose repositories should be scanned.</param>
/// <param name="credential">The credential used for Bitbucket API requests.</param>
/// <param name="username">The username used with app-password authentication.</param>
/// <param name="credentialKind">The credential transport to use for Bitbucket API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference applied to each repository.</param>
/// <param name="includeDownloads">A value indicating whether repository download artifacts should be scanned for each repository.</param>
/// <param name="includeSnippets">A value indicating whether workspace snippets should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested download archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of download archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed download archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum download archive expansion ratio, or 0 for no cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class BitbucketWorkspaceSourceOptions(
    Uri endpoint,
    string workspace,
    string credential,
    string username = "",
    BitbucketCredentialKind credentialKind = BitbucketCredentialKind.BearerToken,
    string gitRef = "",
    bool includeDownloads = false,
    bool includeSnippets = false,
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
    private readonly string _credential = BitbucketSourceOptions.RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Bitbucket Cloud REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = BitbucketSourceOptions.RequireCredentialTransport(
        BitbucketSourceOptions.NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the Bitbucket workspace whose repositories should be scanned.
    /// </summary>
    public string Workspace { get; } = RequireWorkspace(workspace);

    /// <summary>
    /// Gets the credential transport used for Bitbucket API requests.
    /// </summary>
    public BitbucketCredentialKind CredentialKind { get; } = BitbucketSourceOptions.RequireCredentialKind(credentialKind);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference applied to each repository.
    /// </summary>
    public string Ref { get; } = BitbucketSourceOptions.NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets a value indicating whether repository download artifacts should be scanned for each repository.
    /// </summary>
    public bool IncludeDownloads { get; } = includeDownloads;

    /// <summary>
    /// Gets a value indicating whether workspace snippets should be scanned.
    /// </summary>
    public bool IncludeSnippets { get; } = includeSnippets;

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = BitbucketSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested download archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = BitbucketSourceOptions.RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of download archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = BitbucketSourceOptions.RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed download archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = BitbucketSourceOptions.RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum download archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = BitbucketSourceOptions.RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal string Username { get; } = BitbucketSourceOptions.RequireUsername(username, credentialKind);

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    internal BitbucketSourceOptions CreateRepositoryOptions(string repository)
    {
        return new BitbucketSourceOptions(
            Endpoint,
            repository,
            Credential,
            Username,
            CredentialKind,
            Ref,
            includeDownloads: IncludeDownloads,
            maxFileBytes: MaxFileBytes,
            maxArchiveDepth: MaxArchiveDepth,
            maxArchiveEntries: MaxArchiveEntries,
            maxArchiveBytes: MaxArchiveBytes,
            maxArchiveCompressionRatio: MaxArchiveCompressionRatio,
            allowInsecureCredentialTransport: AllowInsecureCredentialTransport,
            isPathAllowed: IsPathAllowed,
            warningSink: WarningSink,
            isCancellationRequested: IsCancellationRequested);
    }

    private static string RequireWorkspace(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim().Trim('/');
        string decoded = Uri.UnescapeDataString(normalized);
        if (decoded.Length == 0
            || decoded.Contains('/')
            || decoded.Contains('\\')
            || decoded.Equals(".", StringComparison.Ordinal)
            || decoded.Equals("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("Bitbucket workspace must be a single workspace slug.", nameof(value));
        }

        return decoded;
    }
}
