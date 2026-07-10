namespace Picket.Sources;

/// <summary>
/// Applies the shared Azure DevOps download-redirect host policy.
/// </summary>
internal static class AzureDevOpsRedirectPolicy
{
    /// <summary>
    /// Determines whether a redirect target is allowed for an Azure DevOps endpoint.
    /// </summary>
    /// <param name="endpoint">The trusted Azure DevOps service endpoint.</param>
    /// <param name="redirectUri">The proposed redirect target.</param>
    /// <returns><see langword="true" /> when the redirect target is allowed.</returns>
    internal static bool IsAllowed(Uri endpoint, Uri redirectUri)
    {
        if (!redirectUri.IsAbsoluteUri
            || !string.IsNullOrEmpty(redirectUri.UserInfo)
            || redirectUri.Scheme is not "https" and not "http")
        {
            return false;
        }

        if (redirectUri.Scheme.Equals("http", StringComparison.Ordinal)
            && !endpoint.Scheme.Equals("http", StringComparison.Ordinal))
        {
            return false;
        }

        bool sameHost = redirectUri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase);
        bool subdomainOfEndpoint = redirectUri.Host.EndsWith(string.Concat(".", endpoint.Host), StringComparison.OrdinalIgnoreCase);
        bool publicAzureDevOpsArtifactHost = IsPublicAzureDevOpsEndpoint(endpoint)
            && (redirectUri.Host.EndsWith(".blob.core.windows.net", StringComparison.OrdinalIgnoreCase)
                || redirectUri.Host.EndsWith(".vsassets.io", StringComparison.OrdinalIgnoreCase)
                || redirectUri.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase));
        return sameHost || subdomainOfEndpoint || publicAzureDevOpsArtifactHost;
    }

    private static bool IsPublicAzureDevOpsEndpoint(Uri endpoint)
    {
        return endpoint.Host.Equals("dev.azure.com", StringComparison.OrdinalIgnoreCase)
            || endpoint.Host.EndsWith(".dev.azure.com", StringComparison.OrdinalIgnoreCase)
            || endpoint.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase);
    }
}
