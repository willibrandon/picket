namespace Picket.Sources;

/// <summary>
/// Configures GitHub repository source enumeration.
/// </summary>
/// <param name="endpoint">The GitHub REST API endpoint.</param>
/// <param name="repository">The repository selector in owner/name form, or a GitHub repository URL.</param>
/// <param name="credential">The credential used for GitHub API requests.</param>
/// <param name="gitRef">An optional branch, tag, or commit reference.</param>
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for no cap.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitHubSourceOptions(
    Uri endpoint,
    string repository,
    string credential,
    string gitRef = "",
    long? maxFileBytes = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private readonly string _credential = RequireCredential(credential);
    private readonly (string Owner, string Name) _repository = ParseRepository(repository);

    /// <summary>
    /// Gets the normalized GitHub REST API endpoint.
    /// </summary>
    public Uri Endpoint { get; } = NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the repository owner or organization.
    /// </summary>
    public string Owner => _repository.Owner;

    /// <summary>
    /// Gets the repository name.
    /// </summary>
    public string RepositoryName => _repository.Name;

    /// <summary>
    /// Gets the repository selector in owner/name form.
    /// </summary>
    public string Repository => string.Concat(_repository.Owner, "/", _repository.Name);

    /// <summary>
    /// Gets the optional branch, tag, or commit reference.
    /// </summary>
    public string Ref { get; } = NormalizeOptionalText(gitRef);

    /// <summary>
    /// Gets the maximum file content bytes to download, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes);

    internal string Credential => _credential;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the default public GitHub REST API endpoint.
    /// </summary>
    /// <returns>The normalized public GitHub REST API endpoint.</returns>
    public static Uri CreateDefaultEndpoint()
    {
        return new Uri("https://api.github.com/", UriKind.Absolute);
    }

    private static Uri NormalizeEndpoint(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not "https" and not "http")
        {
            throw new ArgumentException("GitHub API endpoint must be an absolute HTTP or HTTPS URI.", nameof(endpoint));
        }

        if (!string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("GitHub API endpoint must not include user info, query, or fragment data.", nameof(endpoint));
        }

        string normalized = endpoint.AbsoluteUri;
        if (!normalized.EndsWith('/'))
        {
            normalized = string.Concat(normalized, "/");
        }

        return new Uri(normalized, UriKind.Absolute);
    }

    private static (string Owner, string Name) ParseRepository(string repository)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repository);
        string normalized = repository.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out Uri? repositoryUri))
        {
            string[] uriSegments = repositoryUri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (uriSegments.Length >= 2)
            {
                return ValidateRepositorySegments(
                    Uri.UnescapeDataString(uriSegments[0]),
                    StripGitSuffix(Uri.UnescapeDataString(uriSegments[1])));
            }
        }

        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length != 2)
        {
            throw new ArgumentException("GitHub repository must be in owner/name form or be an absolute repository URL.", nameof(repository));
        }

        return ValidateRepositorySegments(segments[0], StripGitSuffix(segments[1]));
    }

    private static (string Owner, string Name) ValidateRepositorySegments(string owner, string name)
    {
        if (string.IsNullOrWhiteSpace(owner) || string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("GitHub repository owner and name must not be empty.");
        }

        return (owner.Trim(), name.Trim());
    }

    private static string StripGitSuffix(string value)
    {
        return value.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value;
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

    private static long? RequireMaxFileBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }
}
