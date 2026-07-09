namespace Picket.Sources;

/// <summary>
/// Configures Bitbucket Cloud repository source enumeration.
/// </summary>
/// <param name="endpoint">The Bitbucket Cloud REST API endpoint.</param>
/// <param name="repository">The repository to scan as a workspace/repository path or repository URL.</param>
/// <param name="credential">The credential used for Bitbucket API requests.</param>
/// <param name="username">The username used with app-password authentication.</param>
/// <param name="credentialKind">The credential transport to use for Bitbucket API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="pullRequestId">An optional pull request ID whose source head should be scanned.</param>
/// <param name="includeDownloads">A value indicating whether repository download artifacts should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested download archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of download archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed download archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum download archive expansion ratio, or 0 for no cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
/// <param name="pipelineId">An optional pipeline ID whose step logs should be scanned.</param>
/// <param name="includePipelineLogs">A value indicating whether selected pipeline step logs should be scanned.</param>
public sealed class BitbucketSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string username = "",
    BitbucketCredentialKind credentialKind = BitbucketCredentialKind.BearerToken,
    string gitRef = "",
    int pullRequestId = 0,
    bool includeDownloads = false,
    long? maxFileBytes = null,
    int maxArchiveDepth = ArchiveScanDefaults.DefaultMaxDepth,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null,
    string pipelineId = "",
    bool includePipelineLogs = false)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);
    private readonly (string Workspace, string RepositorySlug) _repository = ParseRepository(repository);

    /// <summary>
    /// Gets the normalized Bitbucket Cloud REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the normalized workspace/repository repository path.
    /// </summary>
    public string Repository => string.Concat(_repository.Workspace, "/", _repository.RepositorySlug);

    /// <summary>
    /// Gets the Bitbucket workspace.
    /// </summary>
    public string Workspace => _repository.Workspace;

    /// <summary>
    /// Gets the Bitbucket repository slug.
    /// </summary>
    public string RepositorySlug => _repository.RepositorySlug;

    /// <summary>
    /// Gets the credential transport used for Bitbucket API requests.
    /// </summary>
    public BitbucketCredentialKind CredentialKind { get; } = RequireCredentialKind(credentialKind);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeRef(gitRef, pullRequestId);

    /// <summary>
    /// Gets the optional pull request ID whose source head should be scanned.
    /// </summary>
    public int PullRequestId { get; } = RequirePullRequestId(pullRequestId);

    /// <summary>
    /// Gets a value indicating whether repository download artifacts should be scanned.
    /// </summary>
    public bool IncludeDownloads { get; } = RequireIncludeDownloads(includeDownloads, pullRequestId);

    /// <summary>
    /// Gets the optional pipeline ID whose step logs should be scanned.
    /// </summary>
    public string PipelineId { get; } = RequirePipelineId(pipelineId, pullRequestId, includePipelineLogs);

    /// <summary>
    /// Gets a value indicating whether selected pipeline step logs should be scanned.
    /// </summary>
    public bool IncludePipelineLogs { get; } = RequireIncludePipelineLogs(includePipelineLogs, pipelineId);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested download archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of download archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed download archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum download archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal string Username { get; } = RequireUsername(username, credentialKind);

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the default public Bitbucket Cloud REST API endpoint.
    /// </summary>
    /// <returns>The normalized public Bitbucket Cloud REST API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://api.bitbucket.org/2.0/", UriKind.Absolute);
    }

    internal BitbucketSourceOptions CreateForRepository(string repository)
    {
        return new BitbucketSourceOptions(
            Endpoint,
            repository,
            Credential,
            Username,
            CredentialKind,
            includeDownloads: IncludeDownloads,
            maxFileBytes: MaxFileBytes,
            maxArchiveDepth: MaxArchiveDepth,
            maxArchiveEntries: MaxArchiveEntries,
            maxArchiveBytes: MaxArchiveBytes,
            maxArchiveCompressionRatio: MaxArchiveCompressionRatio,
            allowInsecureCredentialTransport: AllowInsecureCredentialTransport,
            isPathAllowed: IsPathAllowed,
            warningSink: WarningSink,
            isCancellationRequested: IsCancellationRequested,
            pipelineId: PipelineId,
            includePipelineLogs: IncludePipelineLogs);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Bitbucket API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Bitbucket API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    internal static string NormalizeOptionalText(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
    }

    private static string NormalizeRef(string value, int pullRequestId)
    {
        string normalized = NormalizeOptionalText(value);
        if (pullRequestId != 0 && normalized.Length != 0)
        {
            throw new ArgumentException("Bitbucket source options accept either a ref or a pull request ID, not both.", nameof(value));
        }

        return normalized;
    }

    internal static Uri RequireCredentialTransport(Uri endpoint, bool allowInsecureCredentialTransport)
    {
        if (!allowInsecureCredentialTransport && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Bitbucket source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static (string Workspace, string RepositorySlug) ParseRepository(string repository)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repository);
        string normalized = repository.Trim();
        bool isRepositoryUrl = false;
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? repositoryUri))
        {
            if (!string.IsNullOrEmpty(repositoryUri.UserInfo)
                || !string.IsNullOrEmpty(repositoryUri.Query)
                || !string.IsNullOrEmpty(repositoryUri.Fragment))
            {
                throw new ArgumentException("Bitbucket repository URLs must not include user info, query, or fragment data.", nameof(repository));
            }

            normalized = NormalizeRepositoryPath(repositoryUri.AbsolutePath);
            isRepositoryUrl = true;
        }

        normalized = normalized.Trim('/');
        if (normalized.StartsWith("2.0/repositories/", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["2.0/repositories/".Length..];
            isRepositoryUrl = true;
        }

        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length < 2 || (!isRepositoryUrl && segments.Length != 2))
        {
            throw new ArgumentException("Bitbucket repository must be a workspace/repository path or repository URL.", nameof(repository));
        }

        return ValidateRepositorySegments(
            Uri.UnescapeDataString(segments[0]),
            StripGitSuffix(Uri.UnescapeDataString(segments[1])));
    }

    private static string NormalizeRepositoryPath(string path)
    {
        string normalized = path.Trim('/');
        if (normalized.StartsWith("2.0/repositories/", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["2.0/repositories/".Length..];
        }

        return normalized;
    }

    private static (string Workspace, string RepositorySlug) ValidateRepositorySegments(string workspace, string repositorySlug)
    {
        if (string.IsNullOrWhiteSpace(workspace) || string.IsNullOrWhiteSpace(repositorySlug))
        {
            throw new ArgumentException("Bitbucket workspace and repository slug must not be empty.");
        }

        return (workspace.Trim(), repositorySlug.Trim());
    }

    private static string StripGitSuffix(string value)
    {
        return value.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value;
    }

    internal static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    internal static string RequireUsername(string value, BitbucketCredentialKind credentialKind)
    {
        if (credentialKind != BitbucketCredentialKind.AppPassword)
        {
            return string.Empty;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    internal static BitbucketCredentialKind RequireCredentialKind(BitbucketCredentialKind value)
    {
        if (value is not BitbucketCredentialKind.BearerToken
            and not BitbucketCredentialKind.AppPassword)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Unsupported Bitbucket token kind.");
        }

        return value;
    }

    private static int RequirePullRequestId(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static bool RequireIncludeDownloads(bool value, int pullRequestId)
    {
        if (value && pullRequestId != 0)
        {
            throw new ArgumentException("Bitbucket source options cannot combine pull request scans with download artifact enumeration.", nameof(value));
        }

        return value;
    }

    private static string RequirePipelineId(string value, int pullRequestId, bool includePipelineLogs)
    {
        string normalized = NormalizeOptionalText(value).Trim('/');
        if (normalized.Length == 0)
        {
            if (includePipelineLogs)
            {
                throw new ArgumentException("Bitbucket pipeline log source scans require --bitbucket-pipeline-id.", nameof(value));
            }

            return string.Empty;
        }

        if (pullRequestId != 0)
        {
            throw new ArgumentException("Bitbucket source options cannot combine pull request scans with pipeline log enumeration.", nameof(value));
        }

        string decoded = Uri.UnescapeDataString(normalized);
        if (decoded.Length == 0
            || decoded.Contains('/')
            || decoded.Contains('\\')
            || decoded.Equals(".", StringComparison.Ordinal)
            || decoded.Equals("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("Bitbucket pipeline ID must be a single pipeline ID or UUID.", nameof(value));
        }

        return decoded;
    }

    private static bool RequireIncludePipelineLogs(bool value, string pipelineId)
    {
        if (!value && NormalizeOptionalText(pipelineId).Trim('/').Length != 0)
        {
            throw new ArgumentException("Bitbucket pipeline source scans require pipeline log enumeration.", nameof(value));
        }

        return value;
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

    internal static int RequireMaxArchiveDepth(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    internal static int RequireMaxArchiveEntries(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    internal static long? RequireMaxArchiveBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    internal static int RequireMaxArchiveCompressionRatio(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }
}
