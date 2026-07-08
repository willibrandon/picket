namespace Picket.Sources;

/// <summary>
/// Configures Amazon S3 source enumeration.
/// </summary>
/// <param name="endpoint">The S3 REST endpoint.</param>
/// <param name="bucket">The bucket to list.</param>
/// <param name="region">The AWS region used for SigV4 signing.</param>
/// <param name="accessKeyId">The AWS access key ID used for SigV4 signing.</param>
/// <param name="secretAccessKey">The AWS secret access key used for SigV4 signing.</param>
/// <param name="sessionToken">An optional AWS session token.</param>
/// <param name="prefix">An optional object key prefix filter.</param>
/// <param name="maxFileBytes">The maximum object content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class S3SourceOptions(
    Uri endpoint,
    string bucket,
    string region,
    string accessKeyId,
    string secretAccessKey,
    string sessionToken = "",
    string prefix = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _secretAccessKey = RequireCredential(secretAccessKey, nameof(secretAccessKey));

    /// <summary>
    /// Gets the normalized S3 REST endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the normalized bucket name.
    /// </summary>
    public string Bucket { get; } = NormalizeBucket(bucket);

    /// <summary>
    /// Gets the normalized AWS region used for SigV4 signing.
    /// </summary>
    public string Region { get; } = NormalizeRegion(region);

    /// <summary>
    /// Gets the AWS access key ID used for SigV4 signing.
    /// </summary>
    public string AccessKeyId { get; } = RequireCredential(accessKeyId, nameof(accessKeyId));

    /// <summary>
    /// Gets the optional AWS session token.
    /// </summary>
    public string SessionToken { get; } = NormalizeOptionalText(sessionToken);

    /// <summary>
    /// Gets the optional object key prefix filter.
    /// </summary>
    public string Prefix { get; } = NormalizeOptionalText(prefix);

    /// <summary>
    /// Gets the maximum object content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string SecretAccessKey => _secretAccessKey;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Creates the default S3 REST endpoint for a region.
    /// </summary>
    /// <param name="region">The AWS region.</param>
    /// <returns>The region-specific S3 endpoint.</returns>
    public static Uri CreateDefaultEndpoint(string region)
    {
        string normalizedRegion = NormalizeRegion(region);
        return new Uri(string.Concat("https://s3.", normalizedRegion, ".amazonaws.com/"), UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("S3 endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("S3 endpoint must not include user info, query, or fragment data.", nameof(endpoint));
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

    private static Uri RequireCredentialTransport(Uri endpoint, bool allowInsecureCredentialTransport)
    {
        if (!allowInsecureCredentialTransport && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("S3 source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static string NormalizeBucket(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim().Trim('/');
        if (normalized.Length == 0 || normalized.Contains('/'))
        {
            throw new ArgumentException("S3 bucket must be a single bucket name.", nameof(value));
        }

        return normalized;
    }

    private static string NormalizeRegion(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static string RequireCredential(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        return value.Trim();
    }

    private static long RequireMaxFileBytes(long? value, string parameterName)
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
}
