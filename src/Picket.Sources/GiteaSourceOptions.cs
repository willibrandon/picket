namespace Picket.Sources;

/// <summary>
/// Configures Gitea repository source enumeration.
/// </summary>
/// <param name="endpoint">The Gitea REST API endpoint.</param>
/// <param name="repository">The repository to scan as an owner/name path or repository URL.</param>
/// <param name="credential">The credential used for Gitea API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="includeIssues">A value indicating whether Gitea issue bodies and comments should be scanned.</param>
/// <param name="issueState">The Gitea issue state filter.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
/// <param name="pullRequestId">An optional pull request ID whose source head should be scanned.</param>
/// <param name="includeReleases">A value indicating whether Gitea release notes and assets should be scanned.</param>
public sealed class GiteaSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string gitRef = "",
    bool includeIssues = false,
    string issueState = GiteaSourceOptions.DefaultIssueState,
    long? maxFileBytes = null,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null,
    int pullRequestId = 0,
    bool includeReleases = false)
{
    /// <summary>
    /// The default Gitea issue state filter.
    /// </summary>
    public const string DefaultIssueState = "all";

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
    public string Ref { get; } = NormalizeRef(gitRef, pullRequestId);

    /// <summary>
    /// Gets a value indicating whether Gitea issue bodies and comments should be scanned.
    /// </summary>
    public bool IncludeIssues { get; } = RequireIncludeIssues(includeIssues, pullRequestId);

    /// <summary>
    /// Gets the Gitea issue state filter.
    /// </summary>
    public string IssueState { get; } = NormalizeIssueState(issueState);

    /// <summary>
    /// Gets a value indicating whether Gitea release notes and assets should be scanned.
    /// </summary>
    public bool IncludeReleases { get; } = RequireIncludeReleases(includeReleases, pullRequestId);

    /// <summary>
    /// Gets the optional pull request ID whose source head should be scanned.
    /// </summary>
    public int PullRequestId { get; } = RequirePullRequestId(pullRequestId);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    internal string Credential => _credential;

    internal bool AllowInsecureCredentialTransport { get; } = allowInsecureCredentialTransport;

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

    internal GiteaSourceOptions CreateForRepository(string repository)
    {
        return new GiteaSourceOptions(
            Endpoint,
            repository,
            Credential,
            includeIssues: IncludeIssues,
            issueState: IssueState,
            maxFileBytes: MaxFileBytes,
            allowInsecureCredentialTransport: AllowInsecureCredentialTransport,
            isPathAllowed: IsPathAllowed,
            warningSink: WarningSink,
            isCancellationRequested: IsCancellationRequested,
            includeReleases: IncludeReleases);
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

    private static string NormalizeRef(string value, int pullRequestId)
    {
        string normalized = NormalizeOptionalText(value);
        if (pullRequestId != 0 && normalized.Length != 0)
        {
            throw new ArgumentException("Gitea source options accept either a ref or a pull request ID, not both.", nameof(value));
        }

        return normalized;
    }

    /// <summary>
    /// Normalizes a Gitea issue state filter.
    /// </summary>
    /// <param name="value">The issue state value.</param>
    /// <returns>The normalized issue state value.</returns>
    public static string NormalizeIssueState(string value)
    {
        string normalized = NormalizeOptionalText(value);
        if (normalized.Length == 0)
        {
            return DefaultIssueState;
        }

        if (normalized.Equals("open", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("closed", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            return normalized.ToLowerInvariant();
        }

        throw new ArgumentException("Gitea issue state must be open, closed, or all.", nameof(value));
    }

    private static bool RequireIncludeIssues(bool value, int pullRequestId)
    {
        if (value && pullRequestId != 0)
        {
            throw new ArgumentException("Gitea source options cannot combine pull request and issue enumeration.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeReleases(bool value, int pullRequestId)
    {
        if (value && pullRequestId != 0)
        {
            throw new ArgumentException("Gitea source options cannot combine pull request and release enumeration.", nameof(value));
        }

        return value;
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

    private static int RequirePullRequestId(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
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
