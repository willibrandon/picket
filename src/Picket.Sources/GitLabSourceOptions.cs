namespace Picket.Sources;

/// <summary>
/// Configures GitLab repository source enumeration.
/// </summary>
/// <param name="endpoint">The GitLab REST API endpoint.</param>
/// <param name="project">The GitLab project path, numeric ID, or project URL.</param>
/// <param name="credential">The credential used for GitLab API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="mergeRequestIid">An optional merge request internal ID whose source head should be scanned.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for the default cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitLabSourceOptions(
    Uri endpoint,
    string project,
    string credential,
    string gitRef = "",
    int mergeRequestIid = 0,
    long? maxFileBytes = null,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private const long DefaultMaxFileBytes = 100_000_000;
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
    /// Gets the maximum file content bytes to download.
    /// </summary>
    public long MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes, nameof(maxFileBytes));

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

    private static string RequireCredential(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static string NormalizeOptionalText(string value)
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
