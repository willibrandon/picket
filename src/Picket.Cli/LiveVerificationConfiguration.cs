using Picket.Verify;

namespace Picket;

internal sealed class LiveVerificationConfiguration(
    Uri? githubApiEndpoint,
    Uri? githubApiProxyEndpoint,
    GitHubSecretLiveValidatorTlsMode? githubApiTlsMode,
    bool allowNonPublicProviderEndpoints,
    TimeSpan? minimumRequestInterval,
    TimeSpan? minimumRequestIntervalPerProvider,
    int? maxProviderRequests,
    int? maxRequestsPerProvider)
{
    internal Uri? GitHubApiEndpoint { get; } = githubApiEndpoint;

    internal Uri? GitHubApiProxyEndpoint { get; } = githubApiProxyEndpoint;

    internal GitHubSecretLiveValidatorTlsMode? GitHubApiTlsMode { get; } = githubApiTlsMode;

    internal bool AllowNonPublicProviderEndpoints { get; } = allowNonPublicProviderEndpoints;

    internal TimeSpan? MinimumRequestInterval { get; } = minimumRequestInterval;

    internal TimeSpan? MinimumRequestIntervalPerProvider { get; } = minimumRequestIntervalPerProvider;

    internal int? MaxProviderRequests { get; } = maxProviderRequests;

    internal int? MaxRequestsPerProvider { get; } = maxRequestsPerProvider;
}
