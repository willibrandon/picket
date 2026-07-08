namespace Picket.Sources;

/// <summary>
/// Configures Google Cloud Storage source enumeration.
/// </summary>
/// <param name="endpoint">The Cloud Storage JSON API endpoint.</param>
/// <param name="bucket">The bucket to list.</param>
/// <param name="credential">The OAuth bearer token used for Cloud Storage requests.</param>
/// <param name="prefix">An optional object name prefix filter.</param>
/// <param name="userProject">An optional requester-pays billing project.</param>
/// <param name="maxFileBytes">The maximum object content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GcsSourceOptions(
    Uri endpoint,
    string bucket,
    string credential,
    string prefix = "",
    string userProject = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Cloud Storage JSON API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the normalized bucket name.
    /// </summary>
    public string Bucket { get; } = NormalizeBucket(bucket);

    /// <summary>
    /// Gets the optional object name prefix filter.
    /// </summary>
    public string Prefix { get; } = NormalizeOptionalText(prefix);

    /// <summary>
    /// Gets the optional requester-pays billing project.
    /// </summary>
    public string UserProject { get; } = NormalizeOptionalText(userProject);

    /// <summary>
    /// Gets the maximum object content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Creates the public Cloud Storage JSON API endpoint.
    /// </summary>
    /// <returns>The normalized public Cloud Storage JSON API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://storage.googleapis.com/", UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("GCS endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("GCS endpoint must not include user info, query, or fragment data.", nameof(endpoint));
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
            throw new ArgumentException("GCS source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static string NormalizeBucket(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim().Trim('/');
        if (normalized.Length == 0 || normalized.Contains('/'))
        {
            throw new ArgumentException("GCS bucket must be a single bucket name.", nameof(value));
        }

        return normalized;
    }

    private static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
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
