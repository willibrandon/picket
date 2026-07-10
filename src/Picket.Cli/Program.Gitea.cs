using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsGiteaRepositoryFlag(string arg)
    {
        return arg.Equals("--gitea-repository", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-repository=", StringComparison.Ordinal);
    }

    static bool IsGiteaOrganizationFlag(string arg)
    {
        return arg.Equals("--gitea-organization", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-organization=", StringComparison.Ordinal);
    }

    static bool IsGiteaUserFlag(string arg)
    {
        return arg.Equals("--gitea-user", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-user=", StringComparison.Ordinal);
    }

    static bool IsGiteaRefFlag(string arg)
    {
        return arg.Equals("--gitea-ref", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-ref=", StringComparison.Ordinal);
    }

    static bool IsGiteaPullRequestFlag(string arg)
    {
        return arg.Equals("--gitea-pull-request", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-pull-request=", StringComparison.Ordinal);
    }

    static bool IsGiteaIncludeIssuesFlag(string arg)
    {
        return arg.Equals("--gitea-include-issues", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-include-issues=", StringComparison.Ordinal);
    }

    static bool IsGiteaIssueStateFlag(string arg)
    {
        return arg.Equals("--gitea-issue-state", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-issue-state=", StringComparison.Ordinal);
    }

    static bool IsGiteaIncludeReleasesFlag(string arg)
    {
        return arg.Equals("--gitea-include-releases", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-include-releases=", StringComparison.Ordinal);
    }

    static bool IsGiteaIncludeActionsArtifactsFlag(string arg)
    {
        return arg.Equals("--gitea-include-actions-artifacts", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-include-actions-artifacts=", StringComparison.Ordinal);
    }

    static bool IsGiteaActionsRunIdFlag(string arg)
    {
        return arg.Equals("--gitea-actions-run-id", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-actions-run-id=", StringComparison.Ordinal);
    }

    static bool IsGiteaGenericPackageOwnerFlag(string arg)
    {
        return arg.Equals("--gitea-generic-package-owner", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-generic-package-owner=", StringComparison.Ordinal);
    }

    static bool IsGiteaGenericPackageNameFlag(string arg)
    {
        return arg.Equals("--gitea-generic-package-name", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-generic-package-name=", StringComparison.Ordinal);
    }

    static bool IsGiteaGenericPackageVersionFlag(string arg)
    {
        return arg.Equals("--gitea-generic-package-version", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-generic-package-version=", StringComparison.Ordinal);
    }

    static bool IsGiteaGenericPackageFileFlag(string arg)
    {
        return arg.Equals("--gitea-generic-package-file", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-generic-package-file=", StringComparison.Ordinal);
    }

    static bool IsGiteaTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--gitea-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-token-env=", StringComparison.Ordinal);
    }

    static bool IsGiteaApiEndpointFlag(string arg)
    {
        return arg.Equals("--gitea-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--gitea-api-endpoint=", StringComparison.Ordinal);
    }

    static bool TryReadPositiveGiteaPullRequestFlag(string[] args, ref int index, out int pullRequestId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--gitea-pull-request", out pullRequestId))
        {
            return false;
        }

        if (pullRequestId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--gitea-pull-request requires a positive integer value");
        return false;
    }

    static bool TryReadPositiveGiteaActionsRunIdFlag(string[] args, ref int index, out int actionRunId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--gitea-actions-run-id", out actionRunId))
        {
            return false;
        }

        if (actionRunId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--gitea-actions-run-id requires a positive integer value");
        return false;
    }

    static bool TryReadGiteaIssueStateFlag(string[] args, ref int index, out string issueState)
    {
        issueState = GiteaSourceOptions.DefaultIssueState;
        if (!TryReadStringFlag(args, ref index, "--gitea-issue-state", out string? value))
        {
            return false;
        }

        try
        {
            issueState = GiteaSourceOptions.NormalizeIssueState(value);
            return true;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }
    }

    static bool TryCreateGiteaSourceProvider(
        Uri? endpoint,
        string repository,
        string organization,
        string userName,
        string gitRef,
        int pullRequestId,
        bool includeIssues,
        string issueState,
        bool includeReleases,
        bool includeActionArtifacts,
        int actionRunId,
        string genericPackageOwner,
        string genericPackageName,
        string genericPackageVersion,
        string genericPackageFile,
        string? tokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool repositorySpecified = !string.IsNullOrWhiteSpace(repository);
        bool organizationSpecified = !string.IsNullOrWhiteSpace(organization);
        bool userSpecified = !string.IsNullOrWhiteSpace(userName);
        bool genericPackageOwnerSpecified = !string.IsNullOrWhiteSpace(genericPackageOwner);
        bool genericPackageCoordinateSpecified = !string.IsNullOrWhiteSpace(genericPackageName)
            || !string.IsNullOrWhiteSpace(genericPackageVersion)
            || !string.IsNullOrWhiteSpace(genericPackageFile);
        bool exactGenericPackageSpecified = genericPackageOwnerSpecified
            && !string.IsNullOrWhiteSpace(genericPackageName)
            && !string.IsNullOrWhiteSpace(genericPackageVersion)
            && !string.IsNullOrWhiteSpace(genericPackageFile);
        bool genericPackageSpecified = genericPackageOwnerSpecified || genericPackageCoordinateSpecified;
        int sourceSelectorCount = 0;
        if (repositorySpecified)
        {
            sourceSelectorCount++;
        }

        if (organizationSpecified)
        {
            sourceSelectorCount++;
        }

        if (userSpecified)
        {
            sourceSelectorCount++;
        }

        if (genericPackageSpecified)
        {
            sourceSelectorCount++;
        }

        if (sourceSelectorCount != 1)
        {
            Console.Error.WriteLine("Gitea source scan requires exactly one of --gitea-repository, --gitea-organization, --gitea-user, or --gitea-generic-package-owner");
            return false;
        }

        if (genericPackageCoordinateSpecified && (!genericPackageOwnerSpecified
            || string.IsNullOrWhiteSpace(genericPackageName)
            || string.IsNullOrWhiteSpace(genericPackageVersion)
            || string.IsNullOrWhiteSpace(genericPackageFile)))
        {
            Console.Error.WriteLine("Gitea generic package scans use either only --gitea-generic-package-owner or all four --gitea-generic-package-* coordinates");
            return false;
        }

        if (genericPackageSpecified
            && (!string.IsNullOrWhiteSpace(gitRef)
                || pullRequestId != 0
                || includeIssues
                || includeReleases
                || includeActionArtifacts
                || actionRunId != 0))
        {
            Console.Error.WriteLine("Gitea generic package scans cannot be combined with repository refs, pull requests, issues, releases, or Actions artifacts");
            return false;
        }

        if (pullRequestId != 0 && !repositorySpecified)
        {
            Console.Error.WriteLine("Gitea pull request source scan requires --gitea-repository");
            return false;
        }

        if (pullRequestId != 0 && !string.IsNullOrWhiteSpace(gitRef))
        {
            Console.Error.WriteLine("Gitea source scan accepts either --gitea-ref or --gitea-pull-request, not both");
            return false;
        }

        if (pullRequestId != 0 && includeIssues)
        {
            Console.Error.WriteLine("Gitea source scan cannot combine --gitea-pull-request with --gitea-include-issues");
            return false;
        }

        if (pullRequestId != 0 && includeReleases)
        {
            Console.Error.WriteLine("Gitea source scan cannot combine --gitea-pull-request with --gitea-include-releases");
            return false;
        }

        if (pullRequestId != 0 && includeActionArtifacts)
        {
            Console.Error.WriteLine("Gitea source scan cannot combine --gitea-pull-request with --gitea-include-actions-artifacts");
            return false;
        }

        if (actionRunId != 0 && !includeActionArtifacts)
        {
            Console.Error.WriteLine("--gitea-actions-run-id requires --gitea-include-actions-artifacts");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Gitea source scan requires --gitea-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"Gitea token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        Uri sourceEndpoint = endpoint ?? GiteaSourceOptions.CreateDefaultEndpoint();
        try
        {
            if (repositorySpecified)
            {
                var validatedOptions = new GiteaSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    gitRef,
                    includeIssues,
                    issueState,
                    pullRequestId: pullRequestId,
                    includeReleases: includeReleases,
                    includeActionArtifacts: includeActionArtifacts,
                    actionRunId: actionRunId,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                sourceEndpoint = validatedOptions.Endpoint;
                repository = validatedOptions.Repository;
                gitRef = validatedOptions.Ref;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
                actionRunId = validatedOptions.ActionRunId;
                pullRequestId = validatedOptions.PullRequestId;
            }
            else if (organizationSpecified)
            {
                var validatedOptions = new GiteaOrganizationSourceOptions(
                    sourceEndpoint,
                    organization,
                    credential,
                    gitRef,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    actionRunId,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                sourceEndpoint = validatedOptions.Endpoint;
                organization = validatedOptions.Organization;
                gitRef = validatedOptions.Ref;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
                actionRunId = validatedOptions.ActionRunId;
            }
            else if (genericPackageSpecified)
            {
                if (exactGenericPackageSpecified)
                {
                    var validatedOptions = new GiteaGenericPackageSourceOptions(
                        sourceEndpoint,
                        genericPackageOwner,
                        genericPackageName,
                        genericPackageVersion,
                        genericPackageFile,
                        credential,
                        allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                    sourceEndpoint = validatedOptions.Endpoint;
                    genericPackageOwner = validatedOptions.Owner;
                    genericPackageName = validatedOptions.PackageName;
                    genericPackageVersion = validatedOptions.PackageVersion;
                    genericPackageFile = validatedOptions.FileName;
                }
                else
                {
                    var validatedOptions = new GiteaGenericPackageOwnerSourceOptions(
                        sourceEndpoint,
                        genericPackageOwner,
                        credential,
                        allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                    sourceEndpoint = validatedOptions.Endpoint;
                    genericPackageOwner = validatedOptions.Owner;
                }
            }
            else
            {
                var validatedOptions = new GiteaUserSourceOptions(
                    sourceEndpoint,
                    userName,
                    credential,
                    gitRef,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    actionRunId,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                sourceEndpoint = validatedOptions.Endpoint;
                userName = validatedOptions.UserName;
                gitRef = validatedOptions.Ref;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
                actionRunId = validatedOptions.ActionRunId;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }

        var endpointGuardOptions = new EndpointGuardOptions
        {
            AllowNonPublicAddresses = allowNonPublicSourceEndpoints,
            RequireHttps = !allowInsecureSourceEndpoints,
        };
        EndpointGuardResult endpointGuardResult = EndpointGuard.Evaluate(sourceEndpoint, endpointGuardOptions);
        if (!endpointGuardResult.IsAllowed)
        {
            Console.Error.WriteLine($"blocked Gitea endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new GiteaSourceClient(httpClient);
            if (genericPackageSpecified)
            {
                if (exactGenericPackageSpecified)
                {
                    return client.EnumerateGenericPackageFileAsync(new GiteaGenericPackageSourceOptions(
                        sourceEndpoint,
                        genericPackageOwner,
                        genericPackageName,
                        genericPackageVersion,
                        genericPackageFile,
                        credential,
                        maxTargetBytes,
                        maxArchiveDepth,
                        maxArchiveEntries,
                        maxArchiveBytes,
                        maxArchiveCompressionRatio,
                        allowInsecureSourceEndpoints,
                        rules.IsGlobalPathAllowed,
                        Console.Error.WriteLine,
                        () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                        cancellationToken).GetAwaiter().GetResult();
                }

                return client.EnumerateGenericPackageFilesAsync(new GiteaGenericPackageOwnerSourceOptions(
                    sourceEndpoint,
                    genericPackageOwner,
                    credential,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    allowInsecureSourceEndpoints,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                    cancellationToken).GetAwaiter().GetResult();
            }

            if (repositorySpecified)
            {
                return client.EnumerateRepositoryFilesAsync(new GiteaSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    gitRef,
                    includeIssues,
                    issueState,
                    maxFileBytes: maxTargetBytes,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints,
                    isPathAllowed: rules.IsGlobalPathAllowed,
                    warningSink: Console.Error.WriteLine,
                    isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
                    pullRequestId: pullRequestId,
                    includeReleases: includeReleases,
                    includeActionArtifacts: includeActionArtifacts,
                    actionRunId: actionRunId,
                    maxArchiveDepth: maxArchiveDepth,
                    maxArchiveEntries: maxArchiveEntries,
                    maxArchiveBytes: maxArchiveBytes,
                    maxArchiveCompressionRatio: maxArchiveCompressionRatio), cancellationToken).GetAwaiter().GetResult();
            }

            if (organizationSpecified)
            {
                return client.EnumerateOrganizationRepositoryFilesAsync(new GiteaOrganizationSourceOptions(
                    sourceEndpoint,
                    organization,
                    credential,
                    gitRef,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    actionRunId,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    allowInsecureSourceEndpoints,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                    cancellationToken).GetAwaiter().GetResult();
            }

            return client.EnumerateUserRepositoryFilesAsync(new GiteaUserSourceOptions(
                sourceEndpoint,
                userName,
                credential,
                gitRef,
                includeIssues,
                issueState,
                includeReleases,
                includeActionArtifacts,
                actionRunId,
                maxTargetBytes,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                cancellationToken).GetAwaiter().GetResult();
        };
        return true;
    }
}
