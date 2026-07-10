namespace Picket.Sources;

/// <summary>
/// Configures Bitbucket Data Center repository source enumeration.
/// </summary>
/// <param name="endpoint">The Bitbucket Data Center REST API endpoint, including the <c>rest/api/1.0</c> path.</param>
/// <param name="projectKey">The project key whose repositories are scanned.</param>
/// <param name="credential">The credential used for Bitbucket Data Center REST requests.</param>
/// <param name="repositorySlug">An optional repository slug. An empty value scans every readable repository in the project.</param>
/// <param name="username">The username used with Basic authentication.</param>
/// <param name="credentialKind">The credential transport used for REST requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="pullRequestId">An optional pull request ID whose source head is scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip a path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class BitbucketDataCenterSourceOptions(
    Uri endpoint,
    string projectKey,
    string credential,
    string repositorySlug = "",
    string username = "",
    BitbucketDataCenterCredentialKind credentialKind = BitbucketDataCenterCredentialKind.BearerToken,
    string gitRef = "",
    int pullRequestId = 0,
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Bitbucket Data Center REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(
        NormalizeEndpoint(endpoint),
        allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the project key whose repositories are scanned.
    /// </summary>
    public string ProjectKey { get; } = RequirePathSegment(projectKey, nameof(projectKey), "project key");

    /// <summary>
    /// Gets the optional repository slug.
    /// </summary>
    public string RepositorySlug { get; } = NormalizeOptionalPathSegment(repositorySlug, nameof(repositorySlug), "repository slug");

    /// <summary>
    /// Gets the credential transport used for REST requests.
    /// </summary>
    public BitbucketDataCenterCredentialKind CredentialKind { get; } = RequireCredentialKind(credentialKind);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeRef(gitRef, pullRequestId);

    /// <summary>
    /// Gets the optional pull request ID whose source head is scanned.
    /// </summary>
    public int PullRequestId { get; } = RequirePullRequestId(pullRequestId, repositorySlug);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes);

    internal string Credential => _credential;

    internal string Username { get; } = RequireUsername(username, credentialKind);

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    internal BitbucketDataCenterSourceOptions CreateForRepository(
        string project,
        string repository,
        string gitRef)
    {
        return new BitbucketDataCenterSourceOptions(
            Endpoint,
            project,
            Credential,
            repository,
            Username,
            CredentialKind,
            gitRef,
            maxFileBytes: MaxFileBytes,
            allowInsecureCredentialTransport: AllowInsecureCredentialTransport,
            isPathAllowed: IsPathAllowed,
            warningSink: WarningSink,
            isCancellationRequested: IsCancellationRequested);
    }

    private static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Bitbucket Data Center API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Bitbucket Data Center API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    private static Uri RequireCredentialTransport(Uri endpoint, bool allowInsecureCredentialTransport)
    {
        if (!allowInsecureCredentialTransport
            && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Bitbucket Data Center credentials require HTTPS unless insecure source endpoints are explicitly allowed.");
        }

        return endpoint;
    }

    private static string RequirePathSegment(string value, string parameterName, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        string normalized = value.Trim();
        if (normalized is "." or ".."
            || normalized.IndexOfAny(['/', '\\', '?', '#']) >= 0
            || normalized.Any(char.IsControl))
        {
            throw new ArgumentException($"Bitbucket Data Center {description} must be one API path segment.", parameterName);
        }

        return normalized;
    }

    private static string NormalizeOptionalPathSegment(string value, string parameterName, string description)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : RequirePathSegment(value, parameterName, description);
    }

    private static string RequireCredential(string credential)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credential);
        return credential;
    }

    private static string RequireUsername(string username, BitbucketDataCenterCredentialKind credentialKind)
    {
        if (credentialKind != BitbucketDataCenterCredentialKind.Basic)
        {
            return string.Empty;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        return username.Trim();
    }

    private static BitbucketDataCenterCredentialKind RequireCredentialKind(BitbucketDataCenterCredentialKind credentialKind)
    {
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentOutOfRangeException(nameof(credentialKind), credentialKind, "Unsupported Bitbucket Data Center credential kind.");
        }

        return credentialKind;
    }

    private static string NormalizeRef(string value, int pullRequestId)
    {
        string normalized = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        if (pullRequestId != 0 && normalized.Length != 0)
        {
            throw new ArgumentException("Bitbucket Data Center scans accept either a ref or a pull request ID, not both.", nameof(value));
        }

        return normalized;
    }

    private static int RequirePullRequestId(int pullRequestId, string repositorySlug)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(pullRequestId);
        if (pullRequestId != 0 && string.IsNullOrWhiteSpace(repositorySlug))
        {
            throw new ArgumentException("Bitbucket Data Center pull request scans require a repository slug.", nameof(repositorySlug));
        }

        return pullRequestId;
    }

    private static long RequireMaxFileBytes(long? maxFileBytes)
    {
        long value = maxFileBytes ?? DefaultMaxFileBytes;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, 0);
        return value;
    }
}
