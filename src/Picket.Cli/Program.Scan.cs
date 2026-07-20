using Picket.Sources;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static int RunScan(string[] args)
    {
        return RunScan(args, CancellationToken.None);
    }

    static int RunScan(string[] args, CancellationToken cancellationToken)
    {
        var forwardedArgs = new List<string>();
        bool allowNonPublicProviderEndpoints = false;
        bool liveVerification = false;
        Uri? githubApiEndpoint = null;
        Uri? githubApiProxyEndpoint = null;
        GitHubSecretLiveValidatorTlsMode? githubApiTlsMode = null;
        TimeSpan? minimumRequestInterval = null;
        TimeSpan? minimumRequestIntervalPerProvider = null;
        Uri? bitbucketApiEndpoint = null;
        BitbucketCredentialKind bitbucketCredentialKind = BitbucketCredentialKind.BearerToken;
        bool bitbucketIncludeDownloads = false;
        bool bitbucketIncludePipelineLogs = false;
        bool bitbucketIncludeSnippets = false;
        bool bitbucketOptionSpecified = false;
        string bitbucketPipelineId = string.Empty;
        string bitbucketProject = string.Empty;
        int bitbucketPullRequestId = 0;
        string bitbucketRef = string.Empty;
        string bitbucketRepository = string.Empty;
        string? bitbucketTokenEnvironmentVariable = null;
        string? bitbucketUsernameEnvironmentVariable = null;
        string bitbucketWorkspace = string.Empty;
        Uri? bitbucketDataCenterApiEndpoint = null;
        BitbucketDataCenterCredentialKind bitbucketDataCenterCredentialKind = BitbucketDataCenterCredentialKind.BearerToken;
        bool bitbucketDataCenterOptionSpecified = false;
        string bitbucketDataCenterProject = string.Empty;
        int bitbucketDataCenterPullRequestId = 0;
        string bitbucketDataCenterRef = string.Empty;
        string bitbucketDataCenterRepository = string.Empty;
        string? bitbucketDataCenterTokenEnvironmentVariable = null;
        string? bitbucketDataCenterUsernameEnvironmentVariable = null;
        AzureDevOpsCredentialKind azureDevOpsCredentialKind = AzureDevOpsCredentialKind.PersonalAccessToken;
        Uri? azureDevOpsEndpoint = null;
        string azureDevOpsFeed = string.Empty;
        string? azureDevOpsOrganization = null;
        string azureDevOpsPackage = string.Empty;
        string azureDevOpsPackageVersion = string.Empty;
        string? azureDevOpsTokenEnvironmentVariable = null;
        string azureDevOpsBranch = string.Empty;
        string azureDevOpsProject = string.Empty;
        string azureDevOpsRepository = string.Empty;
        int azureDevOpsBuildId = 0;
        int azureDevOpsPullRequestId = 0;
        int azureDevOpsReleaseId = 0;
        long? azureDevOpsMaxArtifactBytes = null;
        long? azureDevOpsMaxLogBytes = null;
        long? azureDevOpsMaxPackageBytes = null;
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
        Uri? giteaApiEndpoint = null;
        int giteaActionsRunId = 0;
        bool giteaIncludeActionsArtifacts = false;
        bool giteaIncludeIssues = false;
        bool giteaIncludeReleases = false;
        string giteaIssueState = GiteaSourceOptions.DefaultIssueState;
        bool giteaOptionSpecified = false;
        string giteaGenericPackageFile = string.Empty;
        string giteaGenericPackageName = string.Empty;
        string giteaGenericPackageOwner = string.Empty;
        string giteaGenericPackageVersion = string.Empty;
        string giteaOrganization = string.Empty;
        int giteaPullRequestId = 0;
        string giteaRef = string.Empty;
        string giteaRepository = string.Empty;
        string? giteaTokenEnvironmentVariable = null;
        string giteaUser = string.Empty;
        Uri? gitLabApiEndpoint = null;
        string gitLabGroup = string.Empty;
        bool gitLabIncludeJobArtifacts = false;
        bool gitLabIncludeJobLogs = false;
        bool gitLabIncludePackages = false;
        bool gitLabIncludeSubgroups = false;
        bool gitLabIncludeSnippets = false;
        bool gitLabOptionSpecified = false;
        int gitLabMergeRequestIid = 0;
        int gitLabPipelineId = 0;
        string gitLabProject = string.Empty;
        string gitLabRef = string.Empty;
        string? gitLabTokenEnvironmentVariable = null;
        AzureBlobCredentialKind azureBlobCredentialKind = AzureBlobCredentialKind.BearerToken;
        Uri? azureBlobEndpoint = null;
        string azureBlobContainer = string.Empty;
        bool azureBlobOptionSpecified = false;
        string azureBlobPrefix = string.Empty;
        string? azureBlobTokenEnvironmentVariable = null;
        Uri? gcsEndpoint = null;
        string gcsBucket = string.Empty;
        bool gcsOptionSpecified = false;
        string gcsPrefix = string.Empty;
        string? gcsTokenEnvironmentVariable = null;
        string gcsUserProject = string.Empty;
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
        bool azureDevOpsIncludePackages = false;
        bool azureDevOpsIncludeReleaseArtifacts = false;
        bool azureDevOpsIncludeWikis = false;
        bool azureDevOpsOptionSpecified = false;
        bool containerArchiveOptionSpecified = false;
        bool githubApiEndpointSpecified = false;
        bool githubSourceOptionSpecified = false;
        bool liveProviderOptionSpecified = false;
        string ociArchivePath = string.Empty;
        Uri? registryAuthenticationEndpoint = null;
        Uri? registryEndpoint = null;
        string registryImage = string.Empty;
        long? registryMaxImageBytes = null;
        bool registryOptionSpecified = false;
        string registryPlatform = string.Empty;
        string? registryPasswordEnvironmentVariable = null;
        string? registryTokenEnvironmentVariable = null;
        string? registryUsernameEnvironmentVariable = null;
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
                    return NativeOperationalExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsVerifyFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--verify", out bool verify))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                dockerArchivePath = archivePath;
                containerArchiveOptionSpecified = true;
                continue;
            }

            if (IsOciArchiveFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--oci-archive", out string? archivePath))
                {
                    return NativeOperationalExitCode;
                }

                ociArchivePath = archivePath;
                containerArchiveOptionSpecified = true;
                continue;
            }

            if (IsRegistryImageFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--registry-image", out string? image))
                {
                    return NativeOperationalExitCode;
                }

                registryImage = image;
                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--registry-endpoint", out registryEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryAuthenticationEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--registry-auth-endpoint", out registryAuthenticationEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--registry-token-env", out registryTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryUsernameEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--registry-username-env", out registryUsernameEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryPasswordEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--registry-password-env", out registryPasswordEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryPlatformFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--registry-platform", out string? platform))
                {
                    return NativeOperationalExitCode;
                }

                registryPlatform = platform;
                registryOptionSpecified = true;
                continue;
            }

            if (IsRegistryMaxImageMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--registry-max-image-megabytes", out registryMaxImageBytes))
                {
                    return NativeOperationalExitCode;
                }

                registryOptionSpecified = true;
                continue;
            }

            if (IsGitHubRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-repository", out string? repository))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceRepository = repository;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubOrganizationFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-organization", out string? organization))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceOrganization = organization;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubUserFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-user", out string? userName))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceUser = userName;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubRepositoryTypeFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-repository-type", out string? repositoryType))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceRepositoryType = repositoryType;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubGistFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-gist", out string? gistId))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceGistId = gistId;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubGistsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-gists", out githubSourceIncludeAuthenticatedGists))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                githubSourceUserGists = userName;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-token-env", out githubSourceTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--github-ref", out string? gitRef))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceRef = gitRef;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubPullRequestFlag(arg))
            {
                if (!TryReadPositiveGitHubPullRequestFlag(args, ref i, out githubSourcePullRequestNumber))
                {
                    return NativeOperationalExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubIncludeIssuesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-include-issues", out githubSourceIncludeIssues))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                githubSourceIncludeIssues = true;
                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsGitHubIncludeReleasesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--github-include-releases", out githubSourceIncludeReleases))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                githubSourceOptionSpecified = true;
                continue;
            }

            if (IsBitbucketRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-repository", out string? repository))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketRepository = repository;
                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketWorkspaceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-workspace", out string? workspace))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketWorkspace = workspace;
                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-project", out string? projectKey))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketProject = projectKey;
                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-ref", out string? gitRef))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketRef = gitRef;
                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketPullRequestFlag(arg))
            {
                if (!TryReadPositiveBitbucketPullRequestFlag(args, ref i, out bitbucketPullRequestId))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketIncludeDownloadsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--bitbucket-include-downloads", out bitbucketIncludeDownloads))
                {
                    return NativeOperationalExitCode;
                }

                if (bitbucketIncludeDownloads)
                {
                    bitbucketOptionSpecified = true;
                }

                continue;
            }

            if (IsBitbucketPipelineIdFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-pipeline-id", out string? pipelineId))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketPipelineId = pipelineId;
                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketIncludePipelineLogsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--bitbucket-include-pipeline-logs", out bitbucketIncludePipelineLogs))
                {
                    return NativeOperationalExitCode;
                }

                if (bitbucketIncludePipelineLogs)
                {
                    bitbucketOptionSpecified = true;
                }

                continue;
            }

            if (IsBitbucketIncludeSnippetsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--bitbucket-include-snippets", out bitbucketIncludeSnippets))
                {
                    return NativeOperationalExitCode;
                }

                if (bitbucketIncludeSnippets)
                {
                    bitbucketOptionSpecified = true;
                }

                continue;
            }

            if (IsBitbucketTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-token-env", out bitbucketTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketUsernameEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-username-env", out bitbucketUsernameEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketTokenKindFlag(arg))
            {
                if (!TryReadBitbucketCredentialKindFlag(args, ref i, out bitbucketCredentialKind))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--bitbucket-api-endpoint", out bitbucketApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--bitbucket-data-center-api-endpoint", out bitbucketDataCenterApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-data-center-project", out string? projectKey))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterProject = projectKey;
                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-data-center-repository", out string? repositorySlug))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterRepository = repositorySlug;
                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-data-center-ref", out string? gitRef))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterRef = gitRef;
                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterPullRequestFlag(arg))
            {
                if (!TryReadPositiveBitbucketDataCenterPullRequestFlag(args, ref i, out bitbucketDataCenterPullRequestId))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-data-center-token-env", out bitbucketDataCenterTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterUsernameEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--bitbucket-data-center-username-env", out bitbucketDataCenterUsernameEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsBitbucketDataCenterTokenKindFlag(arg))
            {
                if (!TryReadBitbucketDataCenterCredentialKindFlag(args, ref i, out bitbucketDataCenterCredentialKind))
                {
                    return NativeOperationalExitCode;
                }

                bitbucketDataCenterOptionSpecified = true;
                continue;
            }

            if (IsGitLabProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-project", out string? project))
                {
                    return NativeOperationalExitCode;
                }

                gitLabProject = project;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGiteaRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-repository", out string? repository))
                {
                    return NativeOperationalExitCode;
                }

                giteaRepository = repository;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaOrganizationFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-organization", out string? organization))
                {
                    return NativeOperationalExitCode;
                }

                giteaOrganization = organization;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaUserFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-user", out string? userName))
                {
                    return NativeOperationalExitCode;
                }

                giteaUser = userName;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-ref", out string? gitRef))
                {
                    return NativeOperationalExitCode;
                }

                giteaRef = gitRef;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaPullRequestFlag(arg))
            {
                if (!TryReadPositiveGiteaPullRequestFlag(args, ref i, out giteaPullRequestId))
                {
                    return NativeOperationalExitCode;
                }

                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaIncludeIssuesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitea-include-issues", out giteaIncludeIssues))
                {
                    return NativeOperationalExitCode;
                }

                if (giteaIncludeIssues)
                {
                    giteaOptionSpecified = true;
                }

                continue;
            }

            if (IsGiteaIssueStateFlag(arg))
            {
                if (!TryReadGiteaIssueStateFlag(args, ref i, out giteaIssueState))
                {
                    return NativeOperationalExitCode;
                }

                giteaIncludeIssues = true;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaIncludeReleasesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitea-include-releases", out giteaIncludeReleases))
                {
                    return NativeOperationalExitCode;
                }

                if (giteaIncludeReleases)
                {
                    giteaOptionSpecified = true;
                }

                continue;
            }

            if (IsGiteaIncludeActionsArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitea-include-actions-artifacts", out giteaIncludeActionsArtifacts))
                {
                    return NativeOperationalExitCode;
                }

                if (giteaIncludeActionsArtifacts)
                {
                    giteaOptionSpecified = true;
                }

                continue;
            }

            if (IsGiteaActionsRunIdFlag(arg))
            {
                if (!TryReadPositiveGiteaActionsRunIdFlag(args, ref i, out giteaActionsRunId))
                {
                    return NativeOperationalExitCode;
                }

                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-token-env", out giteaTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaGenericPackageOwnerFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-generic-package-owner", out string? owner))
                {
                    return NativeOperationalExitCode;
                }

                giteaGenericPackageOwner = owner;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaGenericPackageNameFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-generic-package-name", out string? packageName))
                {
                    return NativeOperationalExitCode;
                }

                giteaGenericPackageName = packageName;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaGenericPackageVersionFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-generic-package-version", out string? packageVersion))
                {
                    return NativeOperationalExitCode;
                }

                giteaGenericPackageVersion = packageVersion;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaGenericPackageFileFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitea-generic-package-file", out string? fileName))
                {
                    return NativeOperationalExitCode;
                }

                giteaGenericPackageFile = fileName;
                giteaOptionSpecified = true;
                continue;
            }

            if (IsGiteaApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--gitea-api-endpoint", out giteaApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                giteaOptionSpecified = true;
                continue;
            }

            if (IsGitLabGroupFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-group", out string? group))
                {
                    return NativeOperationalExitCode;
                }

                gitLabGroup = group;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabRefFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitlab-ref", out string? gitRef))
                {
                    return NativeOperationalExitCode;
                }

                gitLabRef = gitRef;
                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabMergeRequestFlag(arg))
            {
                if (!TryReadPositiveGitLabMergeRequestFlag(args, ref i, out gitLabMergeRequestIid))
                {
                    return NativeOperationalExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabPipelineFlag(arg))
            {
                if (!TryReadPositiveGitLabPipelineFlag(args, ref i, out gitLabPipelineId))
                {
                    return NativeOperationalExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabIncludeSnippetsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-snippets", out gitLabIncludeSnippets))
                {
                    return NativeOperationalExitCode;
                }

                if (gitLabIncludeSnippets)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabIncludeJobArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-job-artifacts", out gitLabIncludeJobArtifacts))
                {
                    return NativeOperationalExitCode;
                }

                if (gitLabIncludeJobArtifacts)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabIncludeJobLogsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-job-logs", out gitLabIncludeJobLogs))
                {
                    return NativeOperationalExitCode;
                }

                if (gitLabIncludeJobLogs)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabIncludePackagesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-packages", out gitLabIncludePackages))
                {
                    return NativeOperationalExitCode;
                }

                if (gitLabIncludePackages)
                {
                    gitLabOptionSpecified = true;
                }

                continue;
            }

            if (IsGitLabIncludeSubgroupsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--gitlab-include-subgroups", out gitLabIncludeSubgroups))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsGitLabApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--gitlab-api-endpoint", out gitLabApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                gitLabOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--azure-blob-endpoint", out azureBlobEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobContainerFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-container", out string? container))
                {
                    return NativeOperationalExitCode;
                }

                azureBlobContainer = container;
                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobPrefixFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-prefix", out string? prefix))
                {
                    return NativeOperationalExitCode;
                }

                azureBlobPrefix = prefix;
                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-blob-token-env", out azureBlobTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureBlobTokenKindFlag(arg))
            {
                if (!TryReadAzureBlobCredentialKindFlag(args, ref i, out azureBlobCredentialKind))
                {
                    return NativeOperationalExitCode;
                }

                azureBlobOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsOrganizationFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-organization", out azureDevOpsOrganization))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsGcsBucketFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gcs-bucket", out string? bucket))
                {
                    return NativeOperationalExitCode;
                }

                gcsBucket = bucket;
                gcsOptionSpecified = true;
                continue;
            }

            if (IsGcsEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--gcs-endpoint", out gcsEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                gcsOptionSpecified = true;
                continue;
            }

            if (IsGcsPrefixFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gcs-prefix", out string? prefix))
                {
                    return NativeOperationalExitCode;
                }

                gcsPrefix = prefix;
                gcsOptionSpecified = true;
                continue;
            }

            if (IsGcsTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gcs-token-env", out gcsTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                gcsOptionSpecified = true;
                continue;
            }

            if (IsGcsUserProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gcs-user-project", out string? userProject))
                {
                    return NativeOperationalExitCode;
                }

                gcsUserProject = userProject;
                gcsOptionSpecified = true;
                continue;
            }

            if (IsS3BucketFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-bucket", out string? bucket))
                {
                    return NativeOperationalExitCode;
                }

                s3Bucket = bucket;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3RegionFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-region", out string? region))
                {
                    return NativeOperationalExitCode;
                }

                s3Region = region;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3EndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--s3-endpoint", out s3Endpoint))
                {
                    return NativeOperationalExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3PrefixFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-prefix", out string? prefix))
                {
                    return NativeOperationalExitCode;
                }

                s3Prefix = prefix;
                s3OptionSpecified = true;
                continue;
            }

            if (IsS3AccessKeyIdEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-access-key-id-env", out s3AccessKeyIdEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3SecretAccessKeyEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-secret-access-key-env", out s3SecretAccessKeyEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsS3SessionTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--s3-session-token-env", out s3SessionTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                s3OptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--azure-devops-endpoint", out azureDevOpsEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsTokenEnvironmentVariableFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-token-env", out azureDevOpsTokenEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsTokenKindFlag(arg))
            {
                if (!TryReadAzureDevOpsCredentialKindFlag(args, ref i, out azureDevOpsCredentialKind))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsProjectFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-project", out string? project))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsProject = project;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsRepositoryFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-repository", out string? repository))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsRepository = repository;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsFeedFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-feed", out string? feed))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsFeed = feed;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsPackageFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-package", out string? package))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsPackage = package;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsPackageVersionFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-package-version", out string? packageVersion))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsPackageVersion = packageVersion;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsBranchFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--azure-devops-branch", out string? branch))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsBranch = branch;
                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsPullRequestFlag(arg))
            {
                if (!TryReadPositiveAzureDevOpsPullRequestFlag(args, ref i, out azureDevOpsPullRequestId))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeWikisFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-wikis", out azureDevOpsIncludeWikis))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-artifacts", out azureDevOpsIncludeArtifacts))
                {
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
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
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsIncludeReleaseArtifactsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-release-artifacts", out azureDevOpsIncludeReleaseArtifacts))
                {
                    return NativeOperationalExitCode;
                }

                if (azureDevOpsIncludeReleaseArtifacts)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsIncludePackagesFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--azure-devops-include-packages", out azureDevOpsIncludePackages))
                {
                    return NativeOperationalExitCode;
                }

                if (azureDevOpsIncludePackages)
                {
                    azureDevOpsOptionSpecified = true;
                }

                continue;
            }

            if (IsAzureDevOpsMaxArtifactMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--azure-devops-max-artifact-megabytes", out azureDevOpsMaxArtifactBytes))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsMaxLogMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--azure-devops-max-log-megabytes", out azureDevOpsMaxLogBytes))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAzureDevOpsMaxPackageMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--azure-devops-max-package-megabytes", out azureDevOpsMaxPackageBytes))
                {
                    return NativeOperationalExitCode;
                }

                azureDevOpsOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-source-endpoints", out allowNonPublicSourceEndpoints))
                {
                    return NativeOperationalExitCode;
                }

                sourceEndpointPolicySpecified = true;
                continue;
            }

            if (IsAllowInsecureSourceEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-insecure-source-endpoints", out allowInsecureSourceEndpoints))
                {
                    return NativeOperationalExitCode;
                }

                sourceEndpointPolicySpecified = true;
                continue;
            }

            if (IsGitHubApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-endpoint", out githubApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                githubApiEndpointSpecified = true;
                continue;
            }

            if (IsGitHubApiProxyFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-proxy", out githubApiProxyEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveTlsModeFlag(arg))
            {
                if (!TryReadLiveTlsModeFlag(args, ref i, out GitHubSecretLiveValidatorTlsMode value))
                {
                    return NativeOperationalExitCode;
                }

                githubApiTlsMode = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-rate-limit-ms", out TimeSpan value))
                {
                    return NativeOperationalExitCode;
                }

                minimumRequestInterval = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsLiveProviderRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-provider-rate-limit-ms", out TimeSpan value))
                {
                    return NativeOperationalExitCode;
                }

                minimumRequestIntervalPerProvider = value;
                liveProviderOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return NativeOperationalExitCode;
                }

                liveProviderOptionSpecified = true;
                continue;
            }

            forwardedArgs.Add(arg);
        }

        if ((liveProviderOptionSpecified || (githubApiEndpointSpecified && !githubSourceOptionSpecified)) && !liveVerification)
        {
            Console.Error.WriteLine("live provider options require --verify");
            return NativeOperationalExitCode;
        }

        if (sourceEndpointPolicySpecified && !azureBlobOptionSpecified && !azureDevOpsOptionSpecified && !bitbucketDataCenterOptionSpecified && !bitbucketOptionSpecified && !gcsOptionSpecified && !githubSourceOptionSpecified && !giteaOptionSpecified && !gitLabOptionSpecified && !registryOptionSpecified && !s3OptionSpecified)
        {
            Console.Error.WriteLine("source endpoint policy options require a remote source option");
            return NativeOperationalExitCode;
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        NativeSourceProvider? sourceFileProvider = null;
        int sourceProviderCount = 0;
        sourceProviderCount += azureBlobOptionSpecified ? 1 : 0;
        sourceProviderCount += azureDevOpsOptionSpecified ? 1 : 0;
        sourceProviderCount += bitbucketDataCenterOptionSpecified ? 1 : 0;
        sourceProviderCount += bitbucketOptionSpecified ? 1 : 0;
        sourceProviderCount += containerArchiveOptionSpecified ? 1 : 0;
        sourceProviderCount += gcsOptionSpecified ? 1 : 0;
        sourceProviderCount += githubSourceOptionSpecified ? 1 : 0;
        sourceProviderCount += giteaOptionSpecified ? 1 : 0;
        sourceProviderCount += gitLabOptionSpecified ? 1 : 0;
        sourceProviderCount += registryOptionSpecified ? 1 : 0;
        sourceProviderCount += s3OptionSpecified ? 1 : 0;
        bool remoteSourceOptionSpecified = azureBlobOptionSpecified
            || azureDevOpsOptionSpecified
            || bitbucketDataCenterOptionSpecified
            || bitbucketOptionSpecified
            || gcsOptionSpecified
            || githubSourceOptionSpecified
            || giteaOptionSpecified
            || gitLabOptionSpecified
            || registryOptionSpecified
            || s3OptionSpecified;
        if (sourceProviderCount > 1)
        {
            Console.Error.WriteLine("scan accepts only one native source provider at a time");
            return NativeOperationalExitCode;
        }

        if (remoteSourceOptionSpecified && HasZeroMegabytesFlag(args, "--max-target-megabytes"))
        {
            Console.Error.WriteLine("Remote download byte caps must be greater than zero.");
            return NativeOperationalExitCode;
        }

        if (remoteSourceOptionSpecified && allowInsecureSourceEndpoints)
        {
            Console.Error.WriteLine("warning: --allow-insecure-source-endpoints permits source credentials over HTTP. Use only for trusted local tests or explicitly accepted private environments.");
        }

        if (azureDevOpsOptionSpecified
            && (HasZeroMegabytesFlag(args, "--azure-devops-max-artifact-megabytes")
                || HasZeroMegabytesFlag(args, "--azure-devops-max-log-megabytes")
                || HasZeroMegabytesFlag(args, "--azure-devops-max-package-megabytes")))
        {
            Console.Error.WriteLine("Remote download byte caps must be greater than zero.");
            return NativeOperationalExitCode;
        }

        if (registryOptionSpecified && HasZeroMegabytesFlag(args, "--registry-max-image-megabytes"))
        {
            Console.Error.WriteLine("Remote download byte caps must be greater than zero.");
            return NativeOperationalExitCode;
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
            return NativeOperationalExitCode;
        }

        if (bitbucketOptionSpecified
            && !TryCreateBitbucketSourceProvider(
                bitbucketApiEndpoint,
                bitbucketRepository,
                bitbucketWorkspace,
                bitbucketRef,
                bitbucketProject,
                bitbucketPullRequestId,
                bitbucketIncludeDownloads,
                bitbucketPipelineId,
                bitbucketIncludePipelineLogs,
                bitbucketIncludeSnippets,
                bitbucketTokenEnvironmentVariable,
                bitbucketUsernameEnvironmentVariable,
                bitbucketCredentialKind,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
        }

        if (bitbucketDataCenterOptionSpecified
            && !TryCreateBitbucketDataCenterSourceProvider(
                bitbucketDataCenterApiEndpoint,
                bitbucketDataCenterProject,
                bitbucketDataCenterRepository,
                bitbucketDataCenterRef,
                bitbucketDataCenterPullRequestId,
                bitbucketDataCenterTokenEnvironmentVariable,
                bitbucketDataCenterUsernameEnvironmentVariable,
                bitbucketDataCenterCredentialKind,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
        }

        if (gcsOptionSpecified
            && !TryCreateGcsSourceProvider(
                gcsEndpoint,
                gcsBucket,
                gcsPrefix,
                gcsTokenEnvironmentVariable,
                gcsUserProject,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
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
            return NativeOperationalExitCode;
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
                azureDevOpsIncludePackages,
                azureDevOpsFeed,
                azureDevOpsPackage,
                azureDevOpsPackageVersion,
                azureDevOpsMaxArtifactBytes,
                azureDevOpsMaxLogBytes,
                azureDevOpsMaxPackageBytes,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
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
            return NativeOperationalExitCode;
        }

        if (giteaOptionSpecified
            && !TryCreateGiteaSourceProvider(
                giteaApiEndpoint,
                giteaRepository,
                giteaOrganization,
                giteaUser,
                giteaRef,
                giteaPullRequestId,
                giteaIncludeIssues,
                giteaIssueState,
                giteaIncludeReleases,
                giteaIncludeActionsArtifacts,
                giteaActionsRunId,
                giteaGenericPackageOwner,
                giteaGenericPackageName,
                giteaGenericPackageVersion,
                giteaGenericPackageFile,
                giteaTokenEnvironmentVariable,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
        }

        if (gitLabOptionSpecified
            && !TryCreateGitLabSourceProvider(
                gitLabApiEndpoint,
                gitLabProject,
                gitLabGroup,
                gitLabRef,
                gitLabMergeRequestIid,
                gitLabPipelineId,
                gitLabIncludeSubgroups,
                gitLabIncludeSnippets,
                gitLabIncludeJobArtifacts,
                gitLabIncludeJobLogs,
                gitLabIncludePackages,
                gitLabTokenEnvironmentVariable,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
        }

        if (containerArchiveOptionSpecified
            && !TryCreateContainerArchiveSourceProvider(
                dockerArchivePath,
                ociArchivePath,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
        }

        if (registryOptionSpecified
            && !TryCreateContainerRegistrySourceProvider(
                registryImage,
                registryEndpoint,
                registryAuthenticationEndpoint,
                registryTokenEnvironmentVariable,
                registryUsernameEnvironmentVariable,
                registryPasswordEnvironmentVariable,
                registryPlatform,
                registryMaxImageBytes,
                allowNonPublicSourceEndpoints,
                allowInsecureSourceEndpoints,
                out sourceFileProvider))
        {
            return NativeOperationalExitCode;
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
            sourceFileProvider: sourceFileProvider,
            cancellationToken: cancellationToken);
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
