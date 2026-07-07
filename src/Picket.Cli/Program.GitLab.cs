using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsGitLabProjectFlag(string arg)
    {
        return arg.Equals("--gitlab-project", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-project=", StringComparison.Ordinal);
    }

    static bool IsGitLabGroupFlag(string arg)
    {
        return arg.Equals("--gitlab-group", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-group=", StringComparison.Ordinal);
    }

    static bool IsGitLabRefFlag(string arg)
    {
        return arg.Equals("--gitlab-ref", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-ref=", StringComparison.Ordinal);
    }

    static bool IsGitLabMergeRequestFlag(string arg)
    {
        return arg.Equals("--gitlab-merge-request", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-merge-request=", StringComparison.Ordinal);
    }

    static bool IsGitLabIncludeSnippetsFlag(string arg)
    {
        return arg.Equals("--gitlab-include-snippets", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-include-snippets=", StringComparison.Ordinal);
    }

    static bool IsGitLabIncludeSubgroupsFlag(string arg)
    {
        return arg.Equals("--gitlab-include-subgroups", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-include-subgroups=", StringComparison.Ordinal);
    }

    static bool IsGitLabTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--gitlab-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-token-env=", StringComparison.Ordinal);
    }

    static bool IsGitLabApiEndpointFlag(string arg)
    {
        return arg.Equals("--gitlab-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-api-endpoint=", StringComparison.Ordinal);
    }

    static bool TryReadPositiveGitLabMergeRequestFlag(string[] args, ref int index, out int mergeRequestIid)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--gitlab-merge-request", out mergeRequestIid))
        {
            return false;
        }

        if (mergeRequestIid > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--gitlab-merge-request requires a positive integer value");
        return false;
    }

    static bool TryCreateGitLabSourceProvider(
        Uri? endpoint,
        string project,
        string group,
        string gitRef,
        int mergeRequestIid,
        bool includeSubgroups,
        bool includeSnippets,
        string? tokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool hasProject = !string.IsNullOrWhiteSpace(project);
        bool hasGroup = !string.IsNullOrWhiteSpace(group);
        if (!hasProject && !hasGroup)
        {
            Console.Error.WriteLine("GitLab source scan requires --gitlab-project or --gitlab-group");
            return false;
        }

        if (hasProject && hasGroup)
        {
            Console.Error.WriteLine("GitLab source scan accepts either --gitlab-project or --gitlab-group, not both");
            return false;
        }

        if (hasGroup && mergeRequestIid != 0)
        {
            Console.Error.WriteLine("--gitlab-merge-request requires --gitlab-project");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("GitLab source scan requires --gitlab-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"GitLab token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        Uri sourceEndpoint = endpoint ?? GitLabSourceOptions.CreateDefaultEndpoint();
        try
        {
            if (hasGroup)
            {
                var validatedGroupOptions = new GitLabGroupSourceOptions(
                    sourceEndpoint,
                    group,
                    credential,
                    gitRef,
                    includeSubgroups,
                    includeSnippets);
                sourceEndpoint = validatedGroupOptions.Endpoint;
                group = validatedGroupOptions.Group;
                gitRef = validatedGroupOptions.Ref;
                includeSubgroups = validatedGroupOptions.IncludeSubgroups;
                includeSnippets = validatedGroupOptions.IncludeSnippets;
            }
            else
            {
                var validatedOptions = new GitLabSourceOptions(
                    sourceEndpoint,
                    project,
                    credential,
                    gitRef,
                    mergeRequestIid,
                    includeSnippets);
                sourceEndpoint = validatedOptions.Endpoint;
                project = validatedOptions.Project;
                gitRef = validatedOptions.Ref;
                mergeRequestIid = validatedOptions.MergeRequestIid;
                includeSnippets = validatedOptions.IncludeSnippets;
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
            Console.Error.WriteLine($"blocked GitLab endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new GitLabSourceClient(httpClient);
            if (hasGroup)
            {
                return client.EnumerateGroupRepositoryFilesAsync(new GitLabGroupSourceOptions(
                    sourceEndpoint,
                    group,
                    credential,
                    gitRef,
                    includeSubgroups,
                    includeSnippets,
                    maxTargetBytes,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
            }

            return client.EnumerateRepositoryFilesAsync(new GitLabSourceOptions(
                sourceEndpoint,
                project,
                credential,
                gitRef,
                mergeRequestIid,
                includeSnippets,
                maxTargetBytes,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
