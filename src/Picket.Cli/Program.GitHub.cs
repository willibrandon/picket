using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsGitHubRepositoryFlag(string arg)
    {
        return arg.Equals("--github-repository", StringComparison.Ordinal)
            || arg.StartsWith("--github-repository=", StringComparison.Ordinal);
    }

    static bool IsGitHubOrganizationFlag(string arg)
    {
        return arg.Equals("--github-organization", StringComparison.Ordinal)
            || arg.StartsWith("--github-organization=", StringComparison.Ordinal);
    }

    static bool IsGitHubUserFlag(string arg)
    {
        return arg.Equals("--github-user", StringComparison.Ordinal)
            || arg.StartsWith("--github-user=", StringComparison.Ordinal);
    }

    static bool IsGitHubRepositoryTypeFlag(string arg)
    {
        return arg.Equals("--github-repository-type", StringComparison.Ordinal)
            || arg.StartsWith("--github-repository-type=", StringComparison.Ordinal);
    }

    static bool IsGitHubGistFlag(string arg)
    {
        return arg.Equals("--github-gist", StringComparison.Ordinal)
            || arg.StartsWith("--github-gist=", StringComparison.Ordinal);
    }

    static bool IsGitHubGistsFlag(string arg)
    {
        return arg.Equals("--github-gists", StringComparison.Ordinal)
            || arg.StartsWith("--github-gists=", StringComparison.Ordinal);
    }

    static bool IsGitHubUserGistsFlag(string arg)
    {
        return arg.Equals("--github-user-gists", StringComparison.Ordinal)
            || arg.StartsWith("--github-user-gists=", StringComparison.Ordinal);
    }

    static bool IsGitHubTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--github-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--github-token-env=", StringComparison.Ordinal);
    }

    static bool IsGitHubRefFlag(string arg)
    {
        return arg.Equals("--github-ref", StringComparison.Ordinal)
            || arg.StartsWith("--github-ref=", StringComparison.Ordinal);
    }

    static bool IsGitHubPullRequestFlag(string arg)
    {
        return arg.Equals("--github-pull-request", StringComparison.Ordinal)
            || arg.StartsWith("--github-pull-request=", StringComparison.Ordinal);
    }

    static bool IsGitHubIncludeIssuesFlag(string arg)
    {
        return arg.Equals("--github-include-issues", StringComparison.Ordinal)
            || arg.StartsWith("--github-include-issues=", StringComparison.Ordinal);
    }

    static bool IsGitHubIssueStateFlag(string arg)
    {
        return arg.Equals("--github-issue-state", StringComparison.Ordinal)
            || arg.StartsWith("--github-issue-state=", StringComparison.Ordinal);
    }

    static bool IsGitHubIncludeReleasesFlag(string arg)
    {
        return arg.Equals("--github-include-releases", StringComparison.Ordinal)
            || arg.StartsWith("--github-include-releases=", StringComparison.Ordinal);
    }

    static bool IsGitHubIncludeActionsArtifactsFlag(string arg)
    {
        return arg.Equals("--github-include-actions-artifacts", StringComparison.Ordinal)
            || arg.StartsWith("--github-include-actions-artifacts=", StringComparison.Ordinal);
    }

    static bool IsGitHubSourceApiEndpointFlag(string arg)
    {
        return arg.Equals("--github-source-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--github-source-api-endpoint=", StringComparison.Ordinal);
    }

    static bool TryReadPositiveGitHubPullRequestFlag(string[] args, ref int index, out int pullRequestNumber)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--github-pull-request", out pullRequestNumber))
        {
            return false;
        }

        if (pullRequestNumber > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--github-pull-request requires a positive integer value");
        return false;
    }

    static bool TryReadGitHubIssueStateFlag(string[] args, ref int index, out string issueState)
    {
        issueState = GitHubSourceOptions.DefaultIssueState;
        if (!TryReadStringFlag(args, ref index, "--github-issue-state", out string? value))
        {
            return false;
        }

        try
        {
            issueState = GitHubSourceOptions.NormalizeIssueState(value);
            return true;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }
    }

    static bool TryCreateGitHubSourceProvider(
        Uri? endpoint,
        string repository,
        string organization,
        string userName,
        string repositoryType,
        string gistId,
        bool includeAuthenticatedGists,
        string gistUserName,
        string? tokenEnvironmentVariable,
        string gitRef,
        int pullRequestNumber,
        bool includeIssues,
        string issueState,
        bool includeReleases,
        bool includeActionArtifacts,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool repositorySpecified = !string.IsNullOrWhiteSpace(repository);
        bool organizationSpecified = !string.IsNullOrWhiteSpace(organization);
        bool userSpecified = !string.IsNullOrWhiteSpace(userName);
        bool gistSpecified = !string.IsNullOrWhiteSpace(gistId);
        bool gistUserSpecified = !string.IsNullOrWhiteSpace(gistUserName);
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

        if (gistSpecified)
        {
            sourceSelectorCount++;
        }

        if (includeAuthenticatedGists)
        {
            sourceSelectorCount++;
        }

        if (gistUserSpecified)
        {
            sourceSelectorCount++;
        }

        if (sourceSelectorCount != 1)
        {
            Console.Error.WriteLine("GitHub source scan requires exactly one of --github-repository, --github-organization, --github-user, --github-gist, --github-gists, or --github-user-gists");
            return false;
        }

        if (pullRequestNumber != 0 && !repositorySpecified)
        {
            Console.Error.WriteLine("GitHub pull request source scan requires --github-repository");
            return false;
        }

        if (pullRequestNumber != 0 && !string.IsNullOrWhiteSpace(gitRef))
        {
            Console.Error.WriteLine("GitHub source scan accepts either --github-ref or --github-pull-request, not both");
            return false;
        }

        if (pullRequestNumber != 0 && includeIssues)
        {
            Console.Error.WriteLine("GitHub source scan cannot combine --github-pull-request with --github-include-issues");
            return false;
        }

        if (pullRequestNumber != 0 && includeReleases)
        {
            Console.Error.WriteLine("GitHub source scan cannot combine --github-pull-request with --github-include-releases");
            return false;
        }

        if (pullRequestNumber != 0 && includeActionArtifacts)
        {
            Console.Error.WriteLine("GitHub source scan cannot combine --github-pull-request with --github-include-actions-artifacts");
            return false;
        }

        if (!repositorySpecified && !organizationSpecified && !userSpecified && !string.IsNullOrWhiteSpace(gitRef))
        {
            Console.Error.WriteLine("GitHub source scan accepts --github-ref only with repository, organization, or user scans");
            return false;
        }

        if (!repositorySpecified && !organizationSpecified && !userSpecified && includeIssues)
        {
            Console.Error.WriteLine("GitHub issue source options require --github-repository, --github-organization, or --github-user");
            return false;
        }

        if (!repositorySpecified && !organizationSpecified && !userSpecified && includeReleases)
        {
            Console.Error.WriteLine("GitHub release source options require --github-repository, --github-organization, or --github-user");
            return false;
        }

        if (!repositorySpecified && !organizationSpecified && !userSpecified && includeActionArtifacts)
        {
            Console.Error.WriteLine("GitHub Actions artifact source options require --github-repository, --github-organization, or --github-user");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("GitHub source scan requires --github-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"GitHub token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        Uri sourceEndpoint = endpoint ?? GitHubSourceOptions.CreateDefaultEndpoint();
        try
        {
            if (repositorySpecified)
            {
                var validatedOptions = new GitHubSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    gitRef,
                    pullRequestNumber,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts);
                sourceEndpoint = validatedOptions.Endpoint;
                repository = validatedOptions.Repository;
                gitRef = validatedOptions.Ref;
                pullRequestNumber = validatedOptions.PullRequestNumber;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
            }
            else if (organizationSpecified)
            {
                var validatedOptions = new GitHubOrganizationSourceOptions(
                    sourceEndpoint,
                    organization,
                    credential,
                    gitRef,
                    repositoryType,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts);
                sourceEndpoint = validatedOptions.Endpoint;
                organization = validatedOptions.Organization;
                repositoryType = validatedOptions.RepositoryType;
                gitRef = validatedOptions.Ref;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
            }
            else if (userSpecified)
            {
                var validatedOptions = new GitHubUserSourceOptions(
                    sourceEndpoint,
                    userName,
                    credential,
                    gitRef,
                    repositoryType,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts);
                sourceEndpoint = validatedOptions.Endpoint;
                userName = validatedOptions.UserName;
                repositoryType = validatedOptions.RepositoryType;
                gitRef = validatedOptions.Ref;
                includeIssues = validatedOptions.IncludeIssues;
                issueState = validatedOptions.IssueState;
                includeReleases = validatedOptions.IncludeReleases;
                includeActionArtifacts = validatedOptions.IncludeActionArtifacts;
            }
            else
            {
                var validatedOptions = new GitHubGistSourceOptions(
                    sourceEndpoint,
                    credential,
                    gistId,
                    includeAuthenticatedGists,
                    gistUserName);
                validatedOptions.ValidateSelector();
                sourceEndpoint = validatedOptions.Endpoint;
                gistId = validatedOptions.GistId;
                includeAuthenticatedGists = validatedOptions.IncludeAuthenticatedGists;
                gistUserName = validatedOptions.UserName;
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
            Console.Error.WriteLine($"blocked GitHub endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new GitHubSourceClient(httpClient);
            if (repositorySpecified)
            {
                return client.EnumerateRepositoryFilesAsync(new GitHubSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    gitRef,
                    pullRequestNumber,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
            }

            if (organizationSpecified)
            {
                return client.EnumerateOrganizationRepositoryFilesAsync(new GitHubOrganizationSourceOptions(
                    sourceEndpoint,
                    organization,
                    credential,
                    gitRef,
                    repositoryType,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
            }

            if (userSpecified)
            {
                return client.EnumerateUserRepositoryFilesAsync(new GitHubUserSourceOptions(
                    sourceEndpoint,
                    userName,
                    credential,
                    gitRef,
                    repositoryType,
                    includeIssues,
                    issueState,
                    includeReleases,
                    includeActionArtifacts,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
            }

            return client.EnumerateGistFilesAsync(new GitHubGistSourceOptions(
                sourceEndpoint,
                credential,
                gistId,
                includeAuthenticatedGists,
                gistUserName,
                maxTargetBytes,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
