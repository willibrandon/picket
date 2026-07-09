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

    static bool IsGitLabPipelineFlag(string arg)
    {
        return arg.Equals("--gitlab-pipeline-id", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-pipeline-id=", StringComparison.Ordinal);
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

    static bool IsGitLabIncludeJobArtifactsFlag(string arg)
    {
        return arg.Equals("--gitlab-include-job-artifacts", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-include-job-artifacts=", StringComparison.Ordinal);
    }

    static bool IsGitLabIncludeJobLogsFlag(string arg)
    {
        return arg.Equals("--gitlab-include-job-logs", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-include-job-logs=", StringComparison.Ordinal);
    }

    static bool IsGitLabIncludePackagesFlag(string arg)
    {
        return arg.Equals("--gitlab-include-packages", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-include-packages=", StringComparison.Ordinal);
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

    static bool TryReadPositiveGitLabPipelineFlag(string[] args, ref int index, out int pipelineId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--gitlab-pipeline-id", out pipelineId))
        {
            return false;
        }

        if (pipelineId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--gitlab-pipeline-id requires a positive integer value");
        return false;
    }

    static bool TryCreateGitLabSourceProvider(
        Uri? endpoint,
        string project,
        string group,
        string gitRef,
        int mergeRequestIid,
        int pipelineId,
        bool includeSubgroups,
        bool includeSnippets,
        bool includeJobArtifacts,
        bool includeJobLogs,
        bool includePackages,
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

        if (hasGroup && pipelineId != 0)
        {
            Console.Error.WriteLine("--gitlab-pipeline-id requires --gitlab-project");
            return false;
        }

        if (pipelineId != 0 && !includeJobArtifacts && !includeJobLogs)
        {
            Console.Error.WriteLine("--gitlab-pipeline-id requires --gitlab-include-job-logs or --gitlab-include-job-artifacts");
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
                    includeSnippets,
                    includeJobArtifacts,
                    includeJobLogs,
                    includePackages: includePackages);
                sourceEndpoint = validatedGroupOptions.Endpoint;
                group = validatedGroupOptions.Group;
                gitRef = validatedGroupOptions.Ref;
                includeSubgroups = validatedGroupOptions.IncludeSubgroups;
                includeSnippets = validatedGroupOptions.IncludeSnippets;
                includeJobArtifacts = validatedGroupOptions.IncludeJobArtifacts;
                includeJobLogs = validatedGroupOptions.IncludeJobLogs;
                includePackages = validatedGroupOptions.IncludePackages;
            }
            else
            {
                var validatedOptions = new GitLabSourceOptions(
                    sourceEndpoint,
                    project,
                    credential,
                    gitRef,
                    mergeRequestIid,
                    includeSnippets,
                    includeJobArtifacts,
                    includeJobLogs,
                    pipelineId,
                    includePackages: includePackages);
                sourceEndpoint = validatedOptions.Endpoint;
                project = validatedOptions.Project;
                gitRef = validatedOptions.Ref;
                mergeRequestIid = validatedOptions.MergeRequestIid;
                pipelineId = validatedOptions.PipelineId;
                includeSnippets = validatedOptions.IncludeSnippets;
                includeJobArtifacts = validatedOptions.IncludeJobArtifacts;
                includeJobLogs = validatedOptions.IncludeJobLogs;
                includePackages = validatedOptions.IncludePackages;
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

        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp) =>
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
                    includeJobArtifacts,
                    includeJobLogs,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp),
                    includePackages)).GetAwaiter().GetResult();
            }

            return client.EnumerateRepositoryFilesAsync(new GitLabSourceOptions(
                sourceEndpoint,
                project,
                credential,
                gitRef,
                mergeRequestIid,
                includeSnippets,
                includeJobArtifacts,
                includeJobLogs,
                pipelineId,
                maxTargetBytes,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp),
                includePackages)).GetAwaiter().GetResult();
        };
        return true;
    }
}
