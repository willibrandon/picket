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
/// <param name="maxFileBytes">The maximum file content bytes to download, or <see langword="null" /> for no cap.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class AzureDevOpsSourceOptions(
    Uri endpoint,
    string credential,
    AzureDevOpsCredentialKind credentialKind = AzureDevOpsCredentialKind.PersonalAccessToken,
    string project = "",
    string repository = "",
    string branch = "",
    long? maxFileBytes = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    private readonly string _credential = RequireCredential(credential);

    /// <summary>
    /// Gets the normalized Azure DevOps organization or collection endpoint.
    /// </summary>
    public Uri Endpoint { get; } = NormalizeEndpoint(endpoint);

    /// <summary>
    /// Gets the credential transport kind.
    /// </summary>
    public AzureDevOpsCredentialKind CredentialKind { get; } = RequireCredentialKind(credentialKind);

    /// <summary>
    /// Gets the optional project filter.
    /// </summary>
    public string Project { get; } = NormalizeOptionalName(project);

    /// <summary>
    /// Gets the optional repository name filter.
    /// </summary>
    public string Repository { get; } = NormalizeOptionalName(repository);

    /// <summary>
    /// Gets the optional branch name.
    /// </summary>
    public string Branch { get; } = NormalizeOptionalName(branch);

    /// <summary>
    /// Gets the maximum file content bytes to download, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxFileBytes { get; } = RequireMaxFileBytes(maxFileBytes);

    internal string Credential => _credential;

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

    private static string NormalizeOptionalName(string value)
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
