namespace Picket.Sources;

/// <summary>
/// Configures Azure DevOps source enumeration.
/// </summary>
/// <param name="endpoint">The Azure DevOps organization or collection endpoint.</param>
/// <param name="credential">The credential used for Azure DevOps API requests.</param>
/// <param name="credentialKind">The credential transport kind.</param>
/// <param name="project">An optional project filter.</param>
/// <param name="repository">An optional repository name filter.</param>
/// <param name="branch">An optional branch name.</param>
/// <param name="pullRequestId">An optional pull request ID whose source head should be scanned.</param>
/// <param name="includeWikis">A value indicating whether wiki backing repositories should be scanned.</param>
/// <param name="buildId">An optional Azure Pipelines build ID whose artifacts or logs should be scanned.</param>
/// <param name="includeArtifacts">A value indicating whether build artifacts should be scanned.</param>
/// <param name="includeLogs">A value indicating whether build logs should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArtifactBytes">The maximum build artifact archive bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxLogBytes">The maximum build log bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth to inspect for build artifacts.</param>
/// <param name="maxArchiveEntries">The maximum number of archive entries to inspect for build artifacts.</param>
/// <param name="maxArchiveBytes">The maximum decompressed archive bytes to inspect for build artifacts.</param>
/// <param name="maxArchiveCompressionRatio">The maximum archive compression ratio to allow for build artifacts.</param>
/// <param name="allowInsecureCredentialTransport">A value indicating whether credentials may be sent to non-loopback HTTP endpoints.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a path should be ignored.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class AzureDevOpsSourceOptions(
    Uri endpoint,
    string credential,
    AzureDevOpsCredentialKind credentialKind = AzureDevOpsCredentialKind.PersonalAccessToken,
    string project = "",
    string repository = "",
    string branch = "",
    int pullRequestId = 0,
    bool includeWikis = false,
    int buildId = 0,
    bool includeArtifacts = false,
    bool includeLogs = false,
    long? maxFileBytes = null,
    long? maxArtifactBytes = null,
    long? maxLogBytes = null,
    int maxArchiveDepth = 1,
    int maxArchiveEntries = 4096,
    long? maxArchiveBytes = 512_000_000,
    int maxArchiveCompressionRatio = 1000,
    bool allowInsecureCredentialTransport = false,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Azure DevOps organization or collection endpoint.
    /// </summary>
    public Uri Endpoint { get; } = RequireCredentialTransport(NormalizeEndpoint(endpoint), RequireCredentialKind(credentialKind), allowInsecureCredentialTransport);

    /// <summary>
    /// Gets the credential transport kind.
    /// </summary>
    public AzureDevOpsCredentialKind CredentialKind { get; } = RequireCredentialKind(credentialKind);

    /// <summary>
    /// Gets the optional project filter.
    /// </summary>
    public string Project { get; } = RequireBuildScope(NormalizeOptionalName(project), buildId, includeArtifacts, includeLogs);

    /// <summary>
    /// Gets the optional repository name filter.
    /// </summary>
    public string Repository { get; } = NormalizeOptionalName(repository);

    /// <summary>
    /// Gets the optional branch name.
    /// </summary>
    public string Branch { get; } = NormalizeOptionalName(branch);

    /// <summary>
    /// Gets the optional pull request ID whose source head should be scanned.
    /// </summary>
    public int PullRequestId { get; } = RequirePullRequestId(pullRequestId);

    /// <summary>
    /// Gets a value indicating whether wiki backing repositories should be scanned.
    /// </summary>
    public bool IncludeWikis { get; } = includeWikis;

    /// <summary>
    /// Gets the optional Azure Pipelines build ID whose artifacts or logs should be scanned.
    /// </summary>
    public int BuildId { get; } = RequireBuildId(buildId);

    /// <summary>
    /// Gets a value indicating whether build artifacts should be scanned.
    /// </summary>
    public bool IncludeArtifacts { get; } = includeArtifacts;

    /// <summary>
    /// Gets a value indicating whether build logs should be scanned.
    /// </summary>
    public bool IncludeLogs { get; } = includeLogs;

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum build artifact archive bytes to download.
    /// </summary>
    public long MaxArtifactBytes { get; } = RequireMaxFileBytes(maxArtifactBytes, nameof(maxArtifactBytes));

    /// <summary>
    /// Gets the maximum build log bytes to download.
    /// </summary>
    public long MaxLogBytes { get; } = RequireMaxFileBytes(maxLogBytes, nameof(maxLogBytes));

    /// <summary>
    /// Gets the maximum nested archive depth to inspect for build artifacts.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of archive entries to inspect for build artifacts.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum decompressed archive bytes to inspect for build artifacts.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum archive compression ratio to allow for build artifacts.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Creates a normalized Azure DevOps Services endpoint from an organization name or URL.
    /// </summary>
    /// <param name="organization">The organization name or absolute organization URL.</param>
    /// <returns>The normalized endpoint URI.</returns>
    public static Uri CreateServicesEndpoint(string organization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(organization);
        string trimmedOrganization = organization.Trim();
        if (Uri.TryCreate(trimmedOrganization, UriKind.Absolute, out Uri? endpoint))
        {
            return NormalizeEndpoint(endpoint);
        }

        return NormalizeEndpoint(new Uri(string.Concat(
            "https://dev.azure.com/",
            Uri.EscapeDataString(trimmedOrganization),
            "/")));
    }

    private static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("Azure DevOps endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("Azure DevOps endpoint must not include user info, query, or fragment data.", nameof(endpoint));
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
        return value;
    }

    private static AzureDevOpsCredentialKind RequireCredentialKind(AzureDevOpsCredentialKind value)
    {
        if (value is not AzureDevOpsCredentialKind.PersonalAccessToken
            and not AzureDevOpsCredentialKind.BearerToken)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return value;
    }

    private static Uri RequireCredentialTransport(Uri endpoint, AzureDevOpsCredentialKind credentialKind, bool allowInsecureCredentialTransport)
    {
        if (endpoint.Scheme.Equals("http", StringComparison.Ordinal)
            && !endpoint.IsLoopback
            && !allowInsecureCredentialTransport)
        {
            throw new ArgumentException($"Azure DevOps {credentialKind} credentials require HTTPS unless insecure credential transport is explicitly enabled.", nameof(endpoint));
        }

        return endpoint;
    }

    private static string NormalizeOptionalName(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
    }

    private static long RequireMaxFileBytes(long? value, string parameterName)
    {
        if (!value.HasValue)
        {
            return GitHubSourceOptions.DefaultMaxFileBytes;
        }

        if (value.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, value.Value, "Remote download byte caps must be greater than zero.");
        }

        return value.Value;
    }

    private static int RequireMaxArchiveDepth(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static int RequireMaxArchiveEntries(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static long? RequireMaxArchiveBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    private static int RequireMaxArchiveCompressionRatio(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static int RequirePullRequestId(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static int RequireBuildId(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static string RequireBuildScope(string project, int buildId, bool includeArtifacts, bool includeLogs)
    {
        if (!includeArtifacts && !includeLogs)
        {
            return project;
        }

        if (project.Length == 0)
        {
            throw new ArgumentException("Azure DevOps build artifact and log scanning requires --azure-devops-project.", nameof(project));
        }

        if (buildId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(buildId), "Azure DevOps build artifact and log scanning requires --azure-devops-build-id.");
        }

        return project;
    }
}
