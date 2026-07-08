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
        int azureDevOpsBuildId = 0;
        int azureDevOpsPullRequestId = 0;
        int azureDevOpsReleaseId = 0;
        long? azureDevOpsMaxArtifactBytes = null;
        long? azureDevOpsMaxLogBytes = null;
        string dockerArchivePath = string.Empty;
        Uri? githubSourceApiEndpoint = null;
        bool githubSourceIncludeAuthenticatedGists = false;
        string githubSourceGistId = string.Empty;
        string? githubSourceTokenEnvironmentVariable = null;
        string githubSourceOrganization = string.Empty;
        bool githubSourceIncludeActionsArtifacts = false;
        bool githubSourceIncludeIssues = false;
        bool githubSourceIncludeReleases = false;
        string githubSourceIssueState = GitHubSourceOptions.DefaultIssueState;
        int githubSourcePullRequestNumber = 0;
        string githubSourceRef = string.Empty;
        string githubSourceRepository = string.Empty;
        string githubSourceRepositoryType = GitHubOrganizationSourceOptions.DefaultRepositoryType;
        string githubSourceUser = string.Empty;
        string githubSourceUserGists = string.Empty;
        Uri? gitLabApiEndpoint = null;
        string gitLabGroup = string.Empty;
        bool gitLabIncludeSubgroups = false;
        bool gitLabIncludeSnippets = false;
        bool gitLabOptionSpecified = false;
        int gitLabMergeRequestIid = 0;
        string gitLabProject = string.Empty;
        string gitLabRef = string.Empty;
        string? gitLabTokenEnvironmentVariable = null;
        AzureBlobCredentialKind azureBlobCredentialKind = AzureBlobCredentialKind.BearerToken;
        Uri? azureBlobEndpoint = null;
        string azureBlobContainer = string.Empty;
        bool azureBlobOptionSpecified = false;
        string azureBlobPrefix = string.Empty;
        string? azureBlobTokenEnvironmentVariable = null;
        Uri? s3Endpoint = null;
        string s3Bucket = string.Empty;
        bool s3OptionSpecified = false;
        string s3Prefix = string.Empty;
        string s3Region = string.Empty;
        string? s3AccessKeyIdEnvironmentVariable = null;
        string? s3SecretAccessKeyEnvironmentVariable = null;
        string? s3SessionTokenEnvironmentVariable = null;
        string? source = null;
        bool allowInsecureSourceEndpoints = false;
        bool allowNonPublicSourceEndpoints = false;
        bool azureDevOpsIncludeArtifacts = false;
        bool azureDevOpsIncludeLogs = false;
        bool azureDevOpsIncludeReleaseArtifacts = false;
        bool azureDevOpsIncludeWikis = false;
        bool azureDevOpsOptionSpecified = false;
        bool containerArchiveOptionSpecified = false;
        bool githubApiEndpointSpecified = false;
        bool githubSourceOptionSpecified = false;
        bool liveProviderOptionSpecified = false;
        string ociArchivePath = string.Empty;
        bool sourceEndpointPolicySpecified = false;
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

            if (IsDockerArchiveFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--docker-archive", out string? archivePath))
                {
                    return UnknownFlagExitCode;
                }

                dockerArchivePath = archivePath;
                containerArchiveOptionSpecified = true;
                continue;
            }

            if (IsOciArchiveFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--oci-archive", out string? archivePath))
                {
                    return UnknownFlagExitCode;
                }

                ociArchivePath = archivePath;
                containerArchiveOptionSpecified = true;
                continue;
            }

            if (IsGitHubRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-repository", out string? repository))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceRepository = repository;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubOrganizationFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-organization", out string? organization))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceOrganization = organization;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubUserFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-user", out string? userName))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceUser = userName;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubRepositoryTypeFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-repository-type", out string? repositoryType))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceRepositoryType = repositoryType;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubGistFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-gist", out string? gistId))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceGistId = gistId;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubGistsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-gists", out githubSourceIncludeAuthenticatedGists))
                {
                    return UnknownFlagExitCode;
                }

                if (githubSourceIncludeAuthenticatedGists)
                {
                    githubSourceOptionSpecified = true;
                }

                continue;
            }

            if (IsGitHubUserGistsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-user-gists", out string? userName))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceUserGists = userName;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-token-env", out githubSourceTokenEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-ref", out string? gitRef))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceRef = gitRef;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubPullRequestFlag(arg))
            {
                if (!TryReadPositiveGitHubPullRequestFlag(args, ref i, out githubSourcePullRequestNumber))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubIncludeIssuesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-include-issues", out githubSourceIncludeIssues))
                {
                    return UnknownFlagExitCode;
                }

                if (githubSourceIncludeIssues)
                {
                    githubSourceOptionSpecified = true;
                }

                continue;
            }

            if (IsGitHubIssueStateFlag(arg))
            {
                if (!TryReadGitHubIssueStateFlag(args, ref i, out githubSourceIssueState))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceIncludeIssues = true;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubIncludeReleasesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-include-releases", out githubSourceIncludeReleases))
                {
                    return UnknownFlagExitCode;
                }

                if (githubSourceIncludeReleases)
                {
                    githubSourceOptionSpecified = true;
                }

                continue;
            }

            if (IsGitHubIncludeActionsArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-include-actions-artifacts", out githubSourceIncludeActionsArtifacts))
                {
                    return UnknownFlagExitCode;
                }

                if (githubSourceIncludeActionsArtifacts)
                {
                    githubSourceOptionSpecified = true;
                }

                continue;
            }

            if (IsGitHubSourceApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-source-api-endpoint", out githubSourceApiEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitLabProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-project", out string? project))
                {
                    return UnknownFlagExitCode;
                }

                gitLabProject = project;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabGroupFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-group", out string? group))
                {
                    return UnknownFlagExitCode;
                }

                gitLabGroup = group;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-ref", out string? gitRef))
                {
                    return UnknownFlagExitCode;
                }

                gitLabRef = gitRef;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabMergeRequestFlag(arg))
            {
                if (!TryReadPositiveGitLabMergeRequestFlag(args, ref i, out gitLabMergeRequestIid))
                {
                    return UnknownFlagExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabIncludeSnippetsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-snippets", out gitLabIncludeSnippets))
                {
                    return UnknownFlagExitCode;
                }

                if (gitLabIncludeSnippets)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabIncludeSubgroupsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-subgroups", out gitLabIncludeSubgroups))
                {
                    return UnknownFlagExitCode;
                }

                if (gitLabIncludeSubgroups)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-token-env", out gitLabTokenEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--gitlab-api-endpoint", out gitLabApiEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--azure-blob-endpoint", out azureBlobEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobContainerFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-container", out string? container))
                {
                    return UnknownFlagExitCode;
                }

                azureBlobContainer = container;
                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobPrefixFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-prefix", out string? prefix))
                {
                    return UnknownFlagExitCode;
                }

                azureBlobPrefix = prefix;
                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-token-env", out azureBlobTokenEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobTokenKindFlag(arg))
            {
                if (!TryReadAzureBlobCredentialKindFlag(args, ref i, out azureBlobCredentialKind))
                {
                    return UnknownFlagExitCode;
                }

                azureBlobOptionSpecified = true;
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

            if (IsS3BucketFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-bucket", out string? bucket))
                {
                    return UnknownFlagExitCode;
                }

                s3Bucket = bucket;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3RegionFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-region", out string? region))
                {
                    return UnknownFlagExitCode;
                }

                s3Region = region;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3EndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--s3-endpoint", out s3Endpoint))
                {
                    return UnknownFlagExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3PrefixFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-prefix", out string? prefix))
                {
                    return UnknownFlagExitCode;
                }

                s3Prefix = prefix;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3AccessKeyIdEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-access-key-id-env", out s3AccessKeyIdEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3SecretAccessKeyEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-secret-access-key-env", out s3SecretAccessKeyEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3SessionTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-session-token-env", out s3SessionTokenEnvironmentVariable))
                {
                    return UnknownFlagExitCode;
                }

                s3OptionSpecified = true;
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

            if (IsAzureDevOpsPullRequestFlag(arg))
            {
                if (!TryReadPositiveAzureDevOpsPullRequestFlag(args, ref i, out azureDevOpsPullRequestId))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeWikisFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-wikis", out azureDevOpsIncludeWikis))
                {
                    return UnknownFlagExitCode;
                }

                if (azureDevOpsIncludeWikis)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsBuildIdFlag(arg))
            {
                if (!TryReadPositiveAzureDevOpsBuildIdFlag(args, ref i, out azureDevOpsBuildId))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-artifacts", out azureDevOpsIncludeArtifacts))
                {
                    return UnknownFlagExitCode;
                }

                if (azureDevOpsIncludeArtifacts)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsIncludeLogsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-logs", out azureDevOpsIncludeLogs))
                {
                    return UnknownFlagExitCode;
                }

                if (azureDevOpsIncludeLogs)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsReleaseIdFlag(arg))
            {
                if (!TryReadPositiveAzureDevOpsReleaseIdFlag(args, ref i, out azureDevOpsReleaseId))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeReleaseArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-release-artifacts", out azureDevOpsIncludeReleaseArtifacts))
                {
                    return UnknownFlagExitCode;
                }

                if (azureDevOpsIncludeReleaseArtifacts)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsMaxArtifactMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--azure-devops-max-artifact-megabytes", out azureDevOpsMaxArtifactBytes))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsMaxLogMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--azure-devops-max-log-megabytes", out azureDevOpsMaxLogBytes))
                {
                    return UnknownFlagExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-source-endpoints", out allowNonPublicSourceEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                sourceEndpointPolicySpecified = true;
                continue;
            }

            if (IsAllowInsecureSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-insecure-source-endpoints", out allowInsecureSourceEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                sourceEndpointPolicySpecified = true;
                continue;
            }

            if (IsGitHubApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-endpoint", out githubApiEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                githubApiEndpointSpecified = true;
                continue;
            }

            if (IsGitHubApiProxyFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-proxy", out githubApiProxyEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveTlsModeFlag(arg))
            {
                if (!TryReadLiveTlsModeFlag(args, ref i, out GitHubSecretLiveValidatorTlsMode value))
                {
                    return UnknownFlagExitCode;
                }

                githubApiTlsMode = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-rate-limit-ms", out TimeSpan value))
                {
                    return UnknownFlagExitCode;
                }

                minimumRequestInterval = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveProviderRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-provider-rate-limit-ms", out TimeSpan value))
                {
                    return UnknownFlagExitCode;
                }

                minimumRequestIntervalPerProvider = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                liveProviderOptionSpecified = true;
                continue;
            }

            forwardedArgs.Add(arg);
        }

        if ((liveProviderOptionSpecified || (githubApiEndpointSpecified && !githubSourceOptionSpecified)) && !liveVerification)
        {
            Console.Error.WriteLine("live provider options require --verify");
            return UnknownFlagExitCode;
        }

        if (sourceEndpointPolicySpecified && !azureBlobOptionSpecified && !azureDevOpsOptionSpecified && !githubSourceOptionSpecified && !gitLabOptionSpecified && !s3OptionSpecified)
        {
            Console.Error.WriteLine("source endpoint policy options require a remote source option");
            return UnknownFlagExitCode;
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        NativeSourceProvider? sourceFileProvider = null;
        int sourceProviderCount = 0;
        sourceProviderCount += azureBlobOptionSpecified ? 1 : 0;
        sourceProviderCount += azureDevOpsOptionSpecified ? 1 : 0;
        sourceProviderCount += containerArchiveOptionSpecified ? 1 : 0;
        sourceProviderCount += githubSourceOptionSpecified ? 1 : 0;
        sourceProviderCount += gitLabOptionSpecified ? 1 : 0;
        sourceProviderCount += s3OptionSpecified ? 1 : 0;
        if (sourceProviderCount > 1)
        {
            Console.Error.WriteLine("scan accepts only one native source provider at a time");
            return UnknownFlagExitCode;
        }

        if ((azureBlobOptionSpecified || azureDevOpsOptionSpecified || githubSourceOptionSpecified || gitLabOptionSpecified || s3OptionSpecified)
            && HasZeroMegabytesFlag(args, "--max-target-megabytes"))
        {
            Console.Error.WriteLine("Remote download byte caps must be greater than zero.");
            return UnknownFlagExitCode;
        }

        if (azureDevOpsOptionSpecified
            && (HasZeroMegabytesFlag(args, "--azure-devops-max-artifact-megabytes")
                || HasZeroMegabytesFlag(args, "--azure-devops-max-log-megabytes")))
        {
            Console.Error.WriteLine("Remote download byte caps must be greater than zero.");
            return UnknownFlagExitCode;
        }

        if (azureBlobOptionSpecified
            && !TryCreateAzureBlobSourceProvider(
                azureBlobEndpoint,
                azureBlobContainer,
                azureBlobPrefix,
                azureBlobTokenEnvironmentVariable,
                azureBlobCredentialKind,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
        }

        if (s3OptionSpecified
            && !TryCreateS3SourceProvider(
                s3Endpoint,
                s3Bucket,
                s3Region,
                s3Prefix,
                s3AccessKeyIdEnvironmentVariable,
                s3SecretAccessKeyEnvironmentVariable,
                s3SessionTokenEnvironmentVariable,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
        }

        if (azureDevOpsOptionSpecified
            && !TryCreateAzureDevOpsSourceProvider(
                azureDevOpsOrganization,
                azureDevOpsEndpoint,
                azureDevOpsTokenEnvironmentVariable,
                azureDevOpsCredentialKind,
                azureDevOpsProject,
                azureDevOpsRepository,
                azureDevOpsBranch,
                azureDevOpsPullRequestId,
                azureDevOpsIncludeWikis,
                azureDevOpsBuildId,
                azureDevOpsIncludeArtifacts,
                azureDevOpsIncludeLogs,
                azureDevOpsReleaseId,
                azureDevOpsIncludeReleaseArtifacts,
                azureDevOpsMaxArtifactBytes,
                azureDevOpsMaxLogBytes,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
        }

        if (githubSourceOptionSpecified
            && !TryCreateGitHubSourceProvider(
                githubSourceApiEndpoint ?? githubApiEndpoint,
                githubSourceRepository,
                githubSourceOrganization,
                githubSourceUser,
                githubSourceRepositoryType,
                githubSourceGistId,
                githubSourceIncludeAuthenticatedGists,
                githubSourceUserGists,
                githubSourceTokenEnvironmentVariable,
                githubSourceRef,
                githubSourcePullRequestNumber,
                githubSourceIncludeIssues,
                githubSourceIssueState,
                githubSourceIncludeReleases,
                githubSourceIncludeActionsArtifacts,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
        }

        if (gitLabOptionSpecified
            && !TryCreateGitLabSourceProvider(
                gitLabApiEndpoint,
                gitLabProject,
                gitLabGroup,
                gitLabRef,
                gitLabMergeRequestIid,
                gitLabIncludeSubgroups,
                gitLabIncludeSnippets,
                gitLabTokenEnvironmentVariable,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return UnknownFlagExitCode;
        }

        if (containerArchiveOptionSpecified
            && !TryCreateContainerArchiveSourceProvider(
                dockerArchivePath,
                ociArchivePath,
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

    private static bool HasZeroMegabytesFlag(string[] args, string flagName)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Equals(flagName, StringComparison.Ordinal))
            {
                return i + 1 < args.Length && args[i + 1].Equals("0", StringComparison.Ordinal);
            }

            if (arg.StartsWith(string.Concat(flagName, "="), StringComparison.Ordinal)
                && arg.AsSpan(flagName.Length + 1).SequenceEqual("0"))
            {
                return true;
            }
        }

        return false;
    }
}
