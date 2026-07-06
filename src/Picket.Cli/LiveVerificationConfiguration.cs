namespace Picket;

internal sealed class LiveVerificationConfiguration(
    Uri? githubApiEndpoint,
    Uri? githubApiProxyEndpoint,
    bool allowNonPublicProviderEndpoints)
{
    internal Uri? GitHubApiEndpoint { get; } = githubApiEndpoint;

    internal Uri? GitHubApiProxyEndpoint { get; } = githubApiProxyEndpoint;

    internal bool AllowNonPublicProviderEndpoints { get; } = allowNonPublicProviderEndpoints;
}
