namespace Picket;

internal sealed class LiveVerificationConfiguration(Uri? githubApiEndpoint, bool allowNonPublicProviderEndpoints)
{
    internal Uri? GitHubApiEndpoint { get; } = githubApiEndpoint;

    internal bool AllowNonPublicProviderEndpoints { get; } = allowNonPublicProviderEndpoints;
}
