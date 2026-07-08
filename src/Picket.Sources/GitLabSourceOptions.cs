namespace Picket.Sources;

/// <summary>
/// Configures GitLab repository source enumeration.
/// </summary>
/// <param name="endpoint">The GitLab REST API endpoint.</param>
/// <param name="project">The GitLab project path, numeric ID, or project URL.</param>
/// <param name="credential">The credential used for GitLab API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="mergeRequestIid">An optional merge request internal ID whose source head should be scanned.</param>
/// <param name="includeSnippets">A value indicating whether project snippets should be scanned.</param>
/// <param name="includeJobArtifacts">A value indicating whether GitLab job artifact archives should be scanned.</param>
/// <param name="includeJobLogs">A value indicating whether GitLab job trace logs should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested artifact archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of artifact archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum artifact archive expansion ratio, or 0 for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitLabSourceOptions(
    Uri endpoint,
    string project,
    string credential,
    string gitRef = "",
    int mergeRequestIid = 0,
    bool includeSnippets = false,
    bool includeJobArtifacts = false,
    bool includeJobLogs = false,
    long? maxFileBytes = null,
    int maxArchiveDepth = ArchiveScanDefaults.DefaultMaxDepth,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    internal const long DefaultMaxFileBytes = 100_000_000;
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized GitLab REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the normalized GitLab project path or numeric project ID.
    /// </summary>
    public string Project { get; } = NormalizeProject(project);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeRef(gitRef, mergeRequestIid);

    /// <summary>
    /// Gets the optional merge request internal ID whose source head should be scanned.
    /// </summary>
    public int MergeRequestIid { get; } = RequireMergeRequestIid(mergeRequestIid);

    /// <summary>
    /// Gets a value indicating whether project snippets should be scanned.
    /// </summary>
    public bool IncludeSnippets { get; } = RequireIncludeSnippets(includeSnippets, mergeRequestIid);

    /// <summary>
    /// Gets a value indicating whether GitLab job artifact archives should be scanned.
    /// </summary>
    public bool IncludeJobArtifacts { get; } = RequireIncludeJobArtifacts(includeJobArtifacts, mergeRequestIid);

    /// <summary>
    /// Gets a value indicating whether GitLab job trace logs should be scanned.
    /// </summary>
    public bool IncludeJobLogs { get; } = RequireIncludeJobLogs(includeJobLogs, mergeRequestIid);

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested artifact archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of artifact archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum artifact archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the default public GitLab REST API endpoint.
    /// </summary>
    /// <returns>The normalized public GitLab REST API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://gitlab.com/api/v4/", UriKind.Absolute);
    }

    internal static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("GitLab API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("GitLab API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    private static string NormalizeProject(string project)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(project);
        string normalized = project.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? projectUri))
        {
            string path = projectUri.AbsolutePath.Trim('/');
            if (path.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                path = path[..^4];
            }

            if (path.StartsWith("api/v4/projects/", StringComparison.OrdinalIgnoreCase))
            {
                path = path["api/v4/projects/".Length..];
            }

            if (path.Length != 0)
            {
                return Uri.UnescapeDataString(path);
            }
        }

        if (normalized.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^4];
        }

        normalized = normalized.Trim('/');
        if (normalized.Length == 0)
        {
            throw new ArgumentException("GitLab project must not be empty.", nameof(project));
        }

        return normalized;
    }

    internal static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    internal static string NormalizeOptionalText(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
    }

    private static string NormalizeRef(string value, int mergeRequestIid)
    {
        string normalized = NormalizeOptionalText(value);
        if (mergeRequestIid != 0 && normalized.Length != 0)
        {
            throw new ArgumentException("GitLab source options accept either a ref or a merge request ID, not both.", nameof(value));
        }

        return normalized;
    }

    private static int RequireMergeRequestIid(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static bool RequireIncludeSnippets(bool value, int mergeRequestIid)
    {
        if (value && mergeRequestIid != 0)
        {
            throw new ArgumentException("GitLab source options cannot combine merge request scans with snippet enumeration.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeJobArtifacts(bool value, int mergeRequestIid)
    {
        if (value && mergeRequestIid != 0)
        {
            throw new ArgumentException("GitLab source options cannot combine merge request scans with job artifact enumeration.", nameof(value));
        }

        return value;
    }

    private static bool RequireIncludeJobLogs(bool value, int mergeRequestIid)
    {
        if (value && mergeRequestIid != 0)
        {
            throw new ArgumentException("GitLab source options cannot combine merge request scans with job log enumeration.", nameof(value));
        }

        return value;
    }

    internal static long RequireMaxFileBytes(long? value, string parameterName)
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

    internal static int RequireMaxArchiveDepth(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    internal static int RequireMaxArchiveEntries(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    internal static long? RequireMaxArchiveBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    internal static int RequireMaxArchiveCompressionRatio(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }
}
