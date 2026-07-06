using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static int RunScan(string[] args)
    {
        var forwardedArgs = new List<string>();
        bool allowNonPublicProviderEndpoints = false;
        bool liveVerification = false;
        bool providerOptionSpecified = false;
        Uri? githubApiEndpoint = null;
        Uri? githubApiProxyEndpoint = null;
        GitHubSecretLiveValidatorTlsMode? githubApiTlsMode = null;
        TimeSpan? minimumRequestInterval = null;
        TimeSpan? minimumRequestIntervalPerProvider = null;
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteScanHelp();
                return 0;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsVerifyFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--verify", out bool verify))
                {
                    return UnknownFlagExitCode;
                }

                if (verify)
                {
                    liveVerification = true;
                }

                continue;
            }

            if (IsGitHubApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-endpoint", out githubApiEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                providerOptionSpecified = true;
                continue;
            }

            if (IsGitHubApiProxyFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-proxy", out githubApiProxyEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                providerOptionSpecified = true;
                continue;
            }

            if (IsLiveTlsModeFlag(arg))
            {
                if (!TryReadLiveTlsModeFlag(args, ref i, out GitHubSecretLiveValidatorTlsMode value))
                {
                    return UnknownFlagExitCode;
                }

                githubApiTlsMode = value;
                providerOptionSpecified = true;
                continue;
            }

            if (IsLiveRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-rate-limit-ms", out TimeSpan value))
                {
                    return UnknownFlagExitCode;
                }

                minimumRequestInterval = value;
                providerOptionSpecified = true;
                continue;
            }

            if (IsLiveProviderRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-provider-rate-limit-ms", out TimeSpan value))
                {
                    return UnknownFlagExitCode;
                }

                minimumRequestIntervalPerProvider = value;
                providerOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                providerOptionSpecified = true;
                continue;
            }

            forwardedArgs.Add(arg);
        }

        if (providerOptionSpecified && !liveVerification)
        {
            Console.Error.WriteLine("live provider options require --verify");
            return UnknownFlagExitCode;
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        return RunDirectory(
            [.. forwardedArgs],
            nativeReportFormats: true,
            diagnosticsCommand: "scan",
            defaultRoot: ".",
            allowValidationResultFilters: true,
            liveVerification: liveVerification
                ? new LiveVerificationConfiguration(
                    githubApiEndpoint,
                    githubApiProxyEndpoint,
                    githubApiTlsMode,
                    allowNonPublicProviderEndpoints,
                    minimumRequestInterval,
                    minimumRequestIntervalPerProvider)
                : null);
    }
}
