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
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class BitbucketSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string username = "",
    BitbucketCredentialKind credentialKind = BitbucketCredentialKind.BearerToken,
    string gitRef = "",
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
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
    public string Ref { get; } = NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal string Username { get; } = RequireUsername(username, credentialKind);

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

    private static Uri RequireCredentialTransport(Uri endpoint, bool allowInsecureCredentialTransport)
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

    private static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static string RequireUsername(string value, BitbucketCredentialKind credentialKind)
    {
        if (credentialKind != BitbucketCredentialKind.AppPassword)
        {
            return string.Empty;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static BitbucketCredentialKind RequireCredentialKind(BitbucketCredentialKind value)
    {
        if (value is not BitbucketCredentialKind.BearerToken
            and not BitbucketCredentialKind.AppPassword)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Unsupported Bitbucket token kind.");
        }

        return value;
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
