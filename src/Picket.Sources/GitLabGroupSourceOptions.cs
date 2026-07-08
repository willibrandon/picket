namespace Picket.Sources;

/// <summary>
/// Configures GitLab group project source enumeration.
/// </summary>
/// <param name="endpoint">The GitLab REST API endpoint.</param>
/// <param name="group">The GitLab group path, numeric ID, or group URL.</param>
/// <param name="credential">The credential used for GitLab API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference applied to each group project.</param>
/// <param name="includeSubgroups">A value indicating whether projects in subgroups should be scanned.</param>
/// <param name="includeSnippets">A value indicating whether project snippets should be scanned.</param>
/// <param name="includeJobArtifacts">A value indicating whether GitLab job artifact archives should be scanned for each group project.</param>
/// <param name="includeJobLogs">A value indicating whether GitLab job trace logs should be scanned for each group project.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="maxArchiveDepth">The maximum nested artifact archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of artifact archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum artifact archive expansion ratio, or 0 for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitLabGroupSourceOptions(
    Uri endpoint,
    string group,
    string credential,
    string gitRef = "",
    bool includeSubgroups = false,
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
    private readonly string _credential = GitLabSourceOptions.RequireCredential(credential);

    /// <summary>
    /// Gets the normalized GitLab REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = GitLabSourceOptions.NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the normalized GitLab group path or numeric group ID.
    /// </summary>
    public string Group { get; } = NormalizeGroup(group);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference applied to each group project.
    /// </summary>
    public string Ref { get; } = GitLabSourceOptions.NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets a value indicating whether projects in subgroups should be scanned.
    /// </summary>
    public bool IncludeSubgroups { get; } = includeSubgroups;

    /// <summary>
    /// Gets a value indicating whether project snippets should be scanned.
    /// </summary>
    public bool IncludeSnippets { get; } = includeSnippets;

    /// <summary>
    /// Gets a value indicating whether GitLab job artifact archives should be scanned for each group project.
    /// </summary>
    public bool IncludeJobArtifacts { get; } = includeJobArtifacts;

    /// <summary>
    /// Gets a value indicating whether GitLab job trace logs should be scanned for each group project.
    /// </summary>
    public bool IncludeJobLogs { get; } = includeJobLogs;

    /// <summary>
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = GitLabSourceOptions.RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

    /// <summary>
    /// Gets the maximum nested artifact archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = GitLabSourceOptions.RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of artifact archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = GitLabSourceOptions.RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed artifact archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = GitLabSourceOptions.RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum artifact archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = GitLabSourceOptions.RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    internal string Credential => _credential;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    private static string NormalizeGroup(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        string normalized = group.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? groupUri))
        {
            string path = groupUri.AbsolutePath.Trim('/');
            if (path.StartsWith("api/v4/groups/", StringComparison.OrdinalIgnoreCase))
            {
                path = path["api/v4/groups/".Length..];
            }
            else if (path.StartsWith("groups/", StringComparison.OrdinalIgnoreCase))
            {
                path = path["groups/".Length..];
            }

            if (path.Length != 0)
            {
                return Uri.UnescapeDataString(path);
            }
        }

        normalized = normalized.Trim('/');
        if (normalized.Length == 0)
        {
            throw new ArgumentException("GitLab group must not be empty.", nameof(group));
        }

        return normalized;
    }
}
