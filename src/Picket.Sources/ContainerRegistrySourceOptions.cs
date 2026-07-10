namespace Picket.Sources;

/// <summary>
/// Configures pull-only OCI or Docker registry image enumeration.
/// </summary>
/// <param name="image">The normalized image reference to pull.</param>
/// <param name="endpoint">An optional registry API endpoint override.</param>
/// <param name="credentialKind">The registry credential form.</param>
/// <param name="credential">The bearer token, basic-auth password, or personal access token.</param>
/// <param name="username">The basic-auth username.</param>
/// <param name="authenticationEndpoint">An explicitly trusted token-service endpoint for cross-host basic authentication.</param>
/// <param name="platform">An optional OCI platform filter in <c>os/architecture[/variant]</c> form. Empty scans every manifest in an image index.</param>
/// <param name="maxBlobBytes">The maximum bytes downloaded for one manifest, config, or layer blob.</param>
/// <param name="maxImageBytes">The aggregate byte cap for unique registry image content.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth inside image layers.</param>
/// <param name="maxArchiveEntries">The aggregate maximum files extracted from image layers. It must be positive when archive traversal is enabled.</param>
/// <param name="maxArchiveBytes">The aggregate decompressed byte cap across image layers. It must be positive when archive traversal is enabled.</param>
/// <param name="maxArchiveCompressionRatio">The maximum layer archive expansion ratio. It must be positive when archive traversal is enabled.</param>
/// <param name="maxTargetBytes">The maximum bytes allowed for each yielded file.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether HTTP registry and token-service endpoints are explicitly allowed.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class ContainerRegistrySourceOptions(
    ContainerRegistryImageReference image,
    Uri? endpoint = null,
    ContainerRegistryCredentialKind credentialKind = ContainerRegistryCredentialKind.Anonymous,
    string credential = "",
    string username = "",
    Uri? authenticationEndpoint = null,
    string platform = "",
    long? maxBlobBytes = null,
    long? maxImageBytes = null,
    int maxArchiveDepth = 1,
    int maxArchiveEntries = 4096,
    long? maxArchiveBytes = 512_000_000,
    int maxArchiveCompressionRatio = 1000,
    long? maxTargetBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxBlobBytes = 100_000_000;
    internal const long DefaultMaxImageBytes = 512_000_000;
    internal const long MaxManifestBytes = 10_000_000;
    internal const int MaxIndexManifestCount = 128;
    internal const int MaxLayerCount = 512;
    private readonly (string Credential, string Username) _credentials = NormalizeCredentials(credentialKind, credential, username);

    /// <summary>
    /// Gets the normalized image reference.
    /// </summary>
    public ContainerRegistryImageReference Image { get; } = image ?? throw new ArgumentNullException(nameof(image));

    /// <summary>
    /// Gets the normalized registry API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireTransport(
        NormalizeEndpoint(endpoint ?? image?.DefaultEndpoint ?? throw new ArgumentNullException(nameof(image)), nameof(endpoint)),
        allowInsecureCredentialTransport,
        "Container registry endpoint");

    /// <summary>
    /// Gets the configured credential form.
    /// </summary>
    public ContainerRegistryCredentialKind CredentialKind { get; } = credentialKind;

    /// <summary>
    /// Gets the optional trusted token-service endpoint.
    /// </summary>
    public Uri? AuthenticationEndpoint { get; } = authenticationEndpoint is null
        ? null
        : RequireTransport(
            NormalizeAuthenticationEndpoint(authenticationEndpoint),
            allowInsecureCredentialTransport,
            "Container registry authentication endpoint");

    /// <summary>
    /// Gets the normalized optional OCI platform filter.
    /// </summary>
    public string Platform { get; } = NormalizePlatform(platform);

    /// <summary>
    /// Gets the maximum bytes downloaded for one registry content object.
    /// </summary>
    public long MaxBlobBytes { get; } = RequirePositiveLimit(maxBlobBytes, DefaultMaxBlobBytes, nameof(maxBlobBytes));

    /// <summary>
    /// Gets the aggregate byte cap for unique registry image content.
    /// </summary>
    public long MaxImageBytes { get; } = RequirePositiveLimit(maxImageBytes, DefaultMaxImageBytes, nameof(maxImageBytes));

    /// <summary>
    /// Gets the maximum nested archive depth inside image layers.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireNonNegative(maxArchiveDepth, nameof(maxArchiveDepth));

    /// <summary>
    /// Gets the aggregate maximum files extracted from image layers.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequirePositiveArchiveLimit(maxArchiveDepth, maxArchiveEntries, nameof(maxArchiveEntries));

    /// <summary>
    /// Gets the aggregate decompressed byte cap across image layers.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequirePositiveArchiveLimit(maxArchiveDepth, maxArchiveBytes, nameof(maxArchiveBytes));

    /// <summary>
    /// Gets the maximum archive expansion ratio.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequirePositiveArchiveLimit(
        maxArchiveDepth,
        maxArchiveCompressionRatio,
        nameof(maxArchiveCompressionRatio));

    /// <summary>
    /// Gets the maximum bytes allowed for each yielded file.
    /// </summary>
    public long MaxTargetBytes { get; } = RequirePositiveLimit(maxTargetBytes, DefaultMaxBlobBytes, nameof(maxTargetBytes));

    internal string Credential => _credentials.Credential;

    internal string Username => _credentials.Username;

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    internal static Uri NormalizeEndpoint(Uri endpoint, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(endpoint, parameterName);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Container registry endpoints must be absolute HTTP or HTTPS URIs.", parameterName);
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Container registry endpoints must not include user info, query, or fragment data.", parameterName);
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    internal static string NormalizePlatform(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        string[] segments = value.Trim().Split('/');
        if (segments.Length is < 2 or > 3)
        {
            throw new ArgumentException("Container registry platform must use os/architecture or os/architecture/variant form.", nameof(value));
        }

        for (int i = 0; i < segments.Length; i++)
        {
            segments[i] = NormalizePlatformSegment(segments[i], i == 1);
        }

        return string.Join('/', segments);
    }

    private static Uri NormalizeAuthenticationEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Container registry authentication endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Container registry authentication endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        return endpoint;
    }

    private static (string Credential, string Username) NormalizeCredentials(
        ContainerRegistryCredentialKind credentialKind,
        string credential,
        string username)
    {
        string normalizedCredential = string.IsNullOrWhiteSpace(credential) ? string.Empty : credential;
        string normalizedUsername = string.IsNullOrWhiteSpace(username) ? string.Empty : username;
        switch (credentialKind)
        {
            case ContainerRegistryCredentialKind.Anonymous:
                if (normalizedCredential.Length != 0 || normalizedUsername.Length != 0)
                {
                    throw new ArgumentException("Anonymous container registry pulls must not include credentials.");
                }

                break;
            case ContainerRegistryCredentialKind.BearerToken:
                if (!IsValidBearerToken(normalizedCredential)
                    || normalizedUsername.Length != 0)
                {
                    throw new ArgumentException("Bearer-token container registry pulls require a valid bounded bearer token and no username.");
                }

                break;
            case ContainerRegistryCredentialKind.Basic:
                if (normalizedCredential.Length is 0 or > 65_536
                    || normalizedUsername.Length is 0 or > 1024
                    || normalizedUsername.Contains(':')
                    || ContainsControlCharacter(normalizedCredential)
                    || ContainsControlCharacter(normalizedUsername))
                {
                    throw new ArgumentException("Basic container registry pulls require bounded credentials without control characters and a username without a colon.");
                }

                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(credentialKind), credentialKind, "Unsupported container registry credential kind.");
        }

        return (normalizedCredential, normalizedUsername);
    }

    internal static bool IsValidBearerToken(string value)
    {
        if (value.Length is 0 or > 65_536 || value[0] == '=')
        {
            return false;
        }

        bool padding = false;
        for (int i = 0; i < value.Length; i++)
        {
            char character = value[i];
            if (character == '=')
            {
                padding = true;
                continue;
            }

            if (padding
                || character is not (>= 'a' and <= 'z')
                    and not (>= 'A' and <= 'Z')
                    and not (>= '0' and <= '9')
                    and not '-'
                    and not '.'
                    and not '_'
                    and not '~'
                    and not '+'
                    and not '/')
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainsControlCharacter(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsControl(value[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static Uri RequireTransport(Uri endpoint, bool allowInsecureCredentialTransport, string description)
    {
        if (!allowInsecureCredentialTransport && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(string.Concat(description, " requires HTTPS unless insecure source endpoints are explicitly allowed."));
        }

        return endpoint;
    }

    private static long RequirePositiveLimit(long? value, long defaultValue, string parameterName)
    {
        if (!value.HasValue)
        {
            return defaultValue;
        }

        if (value.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value.Value, "Remote download byte caps must be greater than zero.");
        }

        return value.Value;
    }

    private static int RequireNonNegative(int value, string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value, parameterName);
        return value;
    }

    private static int RequirePositiveArchiveLimit(int maxArchiveDepth, int value, string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value, parameterName);
        if (maxArchiveDepth > 0 && value == 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Remote registry archive limits must be greater than zero while archive traversal is enabled.");
        }

        return value;
    }

    private static long? RequirePositiveArchiveLimit(int maxArchiveDepth, long? value, string parameterName)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value, parameterName);
        }

        if (maxArchiveDepth > 0 && value.GetValueOrDefault() == 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Remote registry archive limits must be greater than zero while archive traversal is enabled.");
        }

        return value;
    }

    private static string NormalizePlatformSegment(string value, bool architecture)
    {
        string normalized = value.Trim().ToLowerInvariant();
        if (architecture)
        {
            normalized = normalized switch
            {
                "aarch64" => "arm64",
                "x64" or "x86_64" => "amd64",
                _ => normalized,
            };
        }

        if (normalized.Length == 0)
        {
            throw new ArgumentException("Container registry platform segments must not be empty.", nameof(value));
        }

        for (int i = 0; i < normalized.Length; i++)
        {
            char character = normalized[i];
            if (character is not (>= 'a' and <= 'z')
                and not (>= '0' and <= '9')
                and not '.'
                and not '_'
                and not '-')
            {
                throw new ArgumentException("Container registry platform contains an unsupported character.", nameof(value));
            }
        }

        return normalized;
    }
}
