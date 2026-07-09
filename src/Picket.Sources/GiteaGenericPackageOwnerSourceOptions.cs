namespace Picket.Sources;

/// <summary>
/// Configures Gitea generic package owner source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="owner">The Gitea package owner.</param>
/// <param name="credential">The credential used for Gitea package requests.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested package archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of package archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed package archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum package archive expansion ratio, or 0 for no cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GiteaGenericPackageOwnerSourceOptions(
    Uri endpoint,
    string owner,
    string credential,
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
    /// Gets the Gitea package owner.
    /// </summary>
    public string Owner { get; } = GiteaOrganizationSourceOptions.NormalizeAccountName(owner, nameof(owner), "Gitea generic package owner must be a name, not a path.");

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GiteaSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested package archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of package archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed package archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum package archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = GiteaGenericPackageSourceOptions.RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    internal GiteaGenericPackageSourceOptions CreateFileOptions(string packageName, string packageVersion, string fileName)
    {
        return new GiteaGenericPackageSourceOptions(
            Endpoint,
            Owner,
            packageName,
            packageVersion,
            fileName,
            Credential,
            MaxFileBytes,
            MaxArchiveDepth,
            MaxArchiveEntries,
            MaxArchiveBytes,
            MaxArchiveCompressionRatio,
            AllowInsecureCredentialTransport,
            IsPathAllowed,
            WarningSink,
            IsCancellationRequested);
    }
}
