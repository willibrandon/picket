namespace Picket.Sources;

/// <summary>
/// Configures exact Gitea generic package file source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="owner">The Gitea package owner.</param>
/// <param name="packageName">The Gitea generic package name.</param>
/// <param name="packageVersion">The Gitea generic package version.</param>
/// <param name="fileName">The Gitea generic package file name.</param>
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
public sealed class GiteaGenericPackageSourceOptions(
    Uri endpoint,
    string owner,
    string packageName,
    string packageVersion,
    string fileName,
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
    /// Gets the Gitea generic package name.
    /// </summary>
    public string PackageName { get; } = NormalizePackageToken(packageName, nameof(packageName), "Gitea generic package name");

    /// <summary>
    /// Gets the Gitea generic package version.
    /// </summary>
    public string PackageVersion { get; } = NormalizePackageVersion(packageVersion);

    /// <summary>
    /// Gets the Gitea generic package file name.
    /// </summary>
    public string FileName { get; } = NormalizePackageToken(fileName, nameof(fileName), "Gitea generic package file name");

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GiteaSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested package archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of package archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed package archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum package archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    private static string NormalizePackageToken(string value, string parameterName, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        string normalized = value.Trim();
        for (int i = 0; i < normalized.Length; i++)
        {
            char c = normalized[i];
            bool allowed = char.IsAsciiLetterOrDigit(c)
                || c is '.' or '-' or '+' or '_';
            if (!allowed)
            {
                throw new ArgumentException($"{subject} can contain only letters, numbers, dots, hyphens, pluses, or underscores.", parameterName);
            }
        }

        return normalized;
    }

    private static string NormalizePackageVersion(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!value.Equals(value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("Gitea generic package version must not include leading or trailing whitespace.", nameof(value));
        }

        if (value.Contains('/', StringComparison.Ordinal)
            || value.Contains('\\', StringComparison.Ordinal))
        {
            throw new ArgumentException("Gitea generic package version must be a single path segment.", nameof(value));
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
}
