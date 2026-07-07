using Picket.Engine;
using Picket.Sources;
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
        AzureDevOpsCredentialKind azureDevOpsCredentialKind = AzureDevOpsCredentialKind.PersonalAccessToken;
        Uri? azureDevOpsEndpoint = null;
        string? azureDevOpsOrganization = null;
        string? azureDevOpsTokenEnvironmentVariable = null;
        string azureDevOpsBranch = string.Empty;
        string azureDevOpsProject = string.Empty;
        string azureDevOpsRepository = string.Empty;
        string? source = null;
        bool allowInsecureSourceEndpoints = false;
        bool allowNonPublicSourceEndpoints = false;
        bool azureDevOpsOptionSpecified = false;
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

            if (IsAzureDevOpsOrganizationFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-organization", out azureDevOpsOrganization))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--azure-devops-endpoint", out azureDevOpsEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-token-env", out azureDevOpsTokenEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsTokenKindFlag(arg))
            {
                if (!TryReadAzureDevOpsCredentialKindFlag(args, ref i, out azureDevOpsCredentialKind))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-project", out string? project))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsProject = project;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-repository", out string? repository))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsRepository = repository;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsBranchFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-branch", out string? branch))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsBranch = branch;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-source-endpoints", out allowNonPublicSourceEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAllowInsecureSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-insecure-source-endpoints", out allowInsecureSourceEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsUnsupportedAzureDevOpsSourceFlag(arg))
            {
                if (!TryReadUnsupportedAzureDevOpsSourceFlag(args, ref i, arg))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
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

        Func<string, CompiledRuleSet, long?, long, List<SourceFile>>? sourceFileProvider = null;
        if (azureDevOpsOptionSpecified
            && !TryCreateAzureDevOpsSourceProvider(
                azureDevOpsOrganization,
                azureDevOpsEndpoint,
                azureDevOpsTokenEnvironmentVariable,
                azureDevOpsCredentialKind,
                azureDevOpsProject,
                azureDevOpsRepository,
                azureDevOpsBranch,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
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
                : null,
            sourceFileProvider: sourceFileProvider);
    }
}
