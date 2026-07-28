namespace Picket.Sources;

/// <summary>
/// Configures Hugging Face source enumeration.
/// </summary>
/// <param name="endpoint">The Hugging Face Hub endpoint.</param>
/// <param name="resourceKind">The selected Hugging Face resource kind.</param>
/// <param name="resourceId">The repository or bucket identifier.</param>
/// <param name="credential">The Hugging Face user access token.</param>
/// <param name="revision">An optional repository branch, tag, or commit.</param>
/// <param name="pullRequestNumber">An optional pull-request number.</param>
/// <param name="includeDiscussions">A value indicating whether repository discussions should be scanned.</param>
/// <param name="bucketPrefix">An optional bucket object prefix.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum archive expansion ratio, or 0 for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class HuggingFaceSourceOptions(
    Uri endpoint,
    HuggingFaceResourceKind resourceKind,
    string resourceId,
    string credential,
    string revision = "",
    int pullRequestNumber = 0,
    bool includeDiscussions = false,
    string bucketPrefix = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    int maxArchiveDepth = ArchiveScanDefaults.DefaultMaxDepth,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    internal const string DefaultRevision = "main";
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Hugging Face Hub endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the selected resource kind.
    /// </summary>
    public HuggingFaceResourceKind ResourceKind { get; } = RequireResourceKind(resourceKind);

    /// <summary>
    /// Gets the normalized repository or bucket identifier.
    /// </summary>
    public string ResourceId { get; } = NormalizeResourceId(resourceId, resourceKind);

    /// <summary>
    /// Gets the selected repository revision.
    /// </summary>
    public string Revision { get; } = NormalizeRevision(revision, resourceKind, pullRequestNumber);

    /// <summary>
    /// Gets the selected pull-request number, or 0 when no pull request is selected.
    /// </summary>
    public int PullRequestNumber { get; } = RequirePullRequestNumber(pullRequestNumber, resourceKind);

    /// <summary>
    /// Gets a value indicating whether repository discussions should be scanned.
    /// </summary>
    public bool IncludeDiscussions { get; } = RequireIncludeDiscussions(includeDiscussions, resourceKind);

    /// <summary>
    /// Gets the optional bucket object prefix.
    /// </summary>
    public string BucketPrefix { get; } = NormalizeBucketPrefix(bucketPrefix, resourceKind);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes);

    /// <summary>
    /// Gets the maximum nested archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireNonNegative(maxArchiveDepth, nameof(maxArchiveDepth));

    /// <summary>
    /// Gets the maximum number of archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireNonNegative(maxArchiveEntries, nameof(maxArchiveEntries));

    /// <summary>
    /// Gets the maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireNonNegative(maxArchiveBytes, nameof(maxArchiveBytes));

    /// <summary>
    /// Gets the maximum archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireNonNegative(
        maxArchiveCompressionRatio,
        nameof(maxArchiveCompressionRatio));

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Creates the public Hugging Face Hub endpoint.
    /// </summary>
    /// <returns>The normalized public endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://huggingface.co/", UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Hugging Face endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException(
                "Hugging Face endpoint must not include user info, query, or fragment data.",
                nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    private static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static Uri RequireCredentialTransport(Uri endpoint, bool allowInsecureCredentialTransport)
    {
        if (!allowInsecureCredentialTransport
            && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Hugging Face source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static HuggingFaceResourceKind RequireResourceKind(HuggingFaceResourceKind value)
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown Hugging Face resource kind.");
        }

        return value;
    }

    private static string NormalizeResourceId(string value, HuggingFaceResourceKind resourceKind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim().Trim('/');
        if (normalized.Contains('\\'))
        {
            throw new ArgumentException("Hugging Face resource identifiers must use forward slashes.", nameof(value));
        }

        string[] segments = normalized.Split('/');
        if (segments.Length == 0
            || segments.Length > 2
            || segments.Any(IsUnsafeSegment))
        {
            throw new ArgumentException(
                "Hugging Face resource identifiers must be a repository name or namespace/name.",
                nameof(value));
        }

        if (resourceKind == HuggingFaceResourceKind.Bucket && segments.Length != 2)
        {
            throw new ArgumentException("Hugging Face bucket identifiers must use namespace/name.", nameof(value));
        }

        return string.Join('/', segments);
    }

    private static string NormalizeRevision(
        string value,
        HuggingFaceResourceKind resourceKind,
        int pullRequestNumber)
    {
        string normalized = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        if (resourceKind == HuggingFaceResourceKind.Bucket)
        {
            if (normalized.Length != 0)
            {
                throw new ArgumentException("Hugging Face buckets do not support revisions.", nameof(value));
            }

            return string.Empty;
        }

        if (pullRequestNumber != 0 && normalized.Length != 0)
        {
            throw new ArgumentException(
                "Hugging Face scans accept either a revision or a pull-request number, not both.",
                nameof(value));
        }

        return pullRequestNumber == 0
            ? normalized.Length == 0 ? DefaultRevision : normalized
            : string.Concat("refs/pr/", pullRequestNumber.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static int RequirePullRequestNumber(int value, HuggingFaceResourceKind resourceKind)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (resourceKind == HuggingFaceResourceKind.Bucket && value != 0)
        {
            throw new ArgumentException("Hugging Face buckets do not support pull requests.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeDiscussions(bool value, HuggingFaceResourceKind resourceKind)
    {
        if (value && resourceKind == HuggingFaceResourceKind.Bucket)
        {
            throw new ArgumentException("Hugging Face buckets do not support discussions.", nameof(value));
        }

        return value;
    }

    private static string NormalizeBucketPrefix(string value, HuggingFaceResourceKind resourceKind)
    {
        string normalized = string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().TrimStart('/').Replace('\\', '/');
        if (resourceKind != HuggingFaceResourceKind.Bucket && normalized.Length != 0)
        {
            throw new ArgumentException(
                "Hugging Face bucket prefixes require a bucket selector.",
                nameof(value));
        }

        if (normalized.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(IsUnsafeSegment))
        {
            throw new ArgumentException("Hugging Face bucket prefixes must not contain relative path segments.", nameof(value));
        }

        return normalized;
    }

    private static long RequireMaxFileBytes(long? value)
    {
        if (!value.HasValue)
        {
            return DefaultMaxFileBytes;
        }

        if (value.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                value.Value,
                "Remote download byte caps must be greater than zero.");
        }

        return value.Value;
    }

    private static int RequireNonNegative(int value, string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value, parameterName);
        return value;
    }

    private static long? RequireNonNegative(long? value, string parameterName)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value, parameterName);
        }

        return value;
    }

    private static bool IsUnsafeSegment(string value)
    {
        return value.Length == 0
            || value.Equals(".", StringComparison.Ordinal)
            || value.Equals("..", StringComparison.Ordinal);
    }
}
