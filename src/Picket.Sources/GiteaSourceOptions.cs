namespace Picket.Sources;

/// <summary>
/// Configures Gitea repository source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="repository">The repository to scan as an owner/name path or repository URL.</param>
/// <param name="credential">The credential used for Gitea API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GiteaSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string gitRef = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);
    private readonly string _repository = NormalizeRepository(repository);

    /// <summary>
    /// Gets the normalized Gitea REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the normalized owner/name repository path.
    /// </summary>
    public string Repository => _repository;

    /// <summary>
    /// Gets the repository owner.
    /// </summary>
    public string Owner => GetOwner(_repository);

    /// <summary>
    /// Gets the repository name.
    /// </summary>
    public string Name => GetName(_repository);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the default public Gitea REST API endpoint.
    /// </summary>
    /// <returns>The normalized public Gitea REST API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://gitea.com/api/v1/", UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Gitea API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Gitea API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
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
            throw new ArgumentException("Gitea source credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static string NormalizeRepository(string repository)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repository);
        string normalized = repository.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? repositoryUri))
        {
            if (!string.IsNullOrEmpty(repositoryUri.UserInfo)
                || !string.IsNullOrEmpty(repositoryUri.Query)
                || !string.IsNullOrEmpty(repositoryUri.Fragment))
            {
                throw new ArgumentException("Gitea repository URLs must not include user info, query, or fragment data.", nameof(repository));
            }

            normalized = repositoryUri.AbsolutePath.Trim('/');
            if (normalized.StartsWith("api/v1/repos/", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized["api/v1/repos/".Length..];
            }
        }

        if (normalized.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^4];
        }

        normalized = Uri.UnescapeDataString(normalized.Trim('/'));
        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2)
        {
            throw new ArgumentException("Gitea repository must be an owner/name path or repository URL.", nameof(repository));
        }

        return string.Concat(segments[0], "/", segments[1]);
    }

    private static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static string GetOwner(string repository)
    {
        int separator = repository.IndexOf('/');
        return repository[..separator];
    }

    private static string GetName(string repository)
    {
        int separator = repository.IndexOf('/');
        return repository[(separator + 1)..];
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
