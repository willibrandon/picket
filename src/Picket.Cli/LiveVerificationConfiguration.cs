namespace Picket;

internal sealed class LiveVerificationConfiguration(
    Uri? githubApiEndpoint,
    Uri? githubApiProxyEndpoint,
    bool allowNonPublicProviderEndpoints,
    TimeSpan? minimumRequestInterval,
    TimeSpan? minimumRequestIntervalPerProvider)
{
    internal Uri? GitHubApiEndpoint { get; } = githubApiEndpoint;

    internal Uri? GitHubApiProxyEndpoint { get; } = githubApiProxyEndpoint;

    internal bool AllowNonPublicProviderEndpoints { get; } = allowNonPublicProviderEndpoints;

    internal TimeSpan? MinimumRequestInterval { get; } = minimumRequestInterval;

    internal TimeSpan? MinimumRequestIntervalPerProvider { get; } = minimumRequestIntervalPerProvider;
}
