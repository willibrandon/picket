namespace Picket.Sources;

/// <summary>
/// Configures Azure Blob Storage source enumeration.
/// </summary>
/// <param name="endpoint">The Blob service endpoint.</param>
/// <param name="container">The container to list.</param>
/// <param name="credential">The credential used for Blob service requests.</param>
/// <param name="credentialKind">The credential transport used for Blob service requests.</param>
/// <param name="prefix">An optional blob name prefix filter.</param>
/// <param name="maxFileBytes">The maximum blob content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class AzureBlobSourceOptions(
    Uri endpoint,
    string container,
    string credential,
    AzureBlobCredentialKind credentialKind = AzureBlobCredentialKind.BearerToken,
    string prefix = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Blob service endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the normalized container name.
    /// </summary>
    public string Container { get; } = NormalizeContainer(container);

    /// <summary>
    /// Gets the credential transport used for Blob service requests.
    /// </summary>
    public AzureBlobCredentialKind CredentialKind { get; } = credentialKind;

    /// <summary>
    /// Gets the optional blob name prefix filter.
    /// </summary>
    public string Prefix { get; } = NormalizeOptionalText(prefix);

    /// <summary>
    /// Gets the maximum blob content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal string SasQuery => CredentialKind == AzureBlobCredentialKind.SharedAccessSignature ? NormalizeSasQuery(_credential) : string.Empty;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Creates the public Azure Blob Storage endpoint for an account.
    /// </summary>
    /// <param name="accountName">The Azure Storage account name.</param>
    /// <returns>The normalized public Blob service endpoint.</returns>
    public static Uri CreatePublicEndpoint(string accountName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        return new Uri(string.Concat("https://", accountName.Trim(), ".blob.core.windows.net/"), UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Azure Blob endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Azure Blob endpoint must not include user info, query, or fragment data.", nameof(endpoint));
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
            throw new ArgumentException("Azure Blob source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static string NormalizeContainer(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim().Trim('/');
        if (normalized.Length == 0 || normalized.Contains('/'))
        {
            throw new ArgumentException("Azure Blob container must be a single container name.", nameof(value));
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

    private static string NormalizeSasQuery(string credential)
    {
        string normalized = credential.Trim();
        while (normalized.StartsWith('?') || normalized.StartsWith('&'))
        {
            normalized = normalized[1..];
        }

        if (normalized.Length == 0)
        {
            throw new ArgumentException("Azure Blob shared access signature must not be empty.", nameof(credential));
        }

        return normalized;
    }
}
