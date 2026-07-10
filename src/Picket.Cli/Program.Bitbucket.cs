using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsBitbucketRepositoryFlag(string arg)
    {
        return arg.Equals("--bitbucket-repository", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-repository=", StringComparison.Ordinal);
    }

    static bool IsBitbucketWorkspaceFlag(string arg)
    {
        return arg.Equals("--bitbucket-workspace", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-workspace=", StringComparison.Ordinal);
    }

    static bool IsBitbucketProjectFlag(string arg)
    {
        return arg.Equals("--bitbucket-project", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-project=", StringComparison.Ordinal);
    }

    static bool IsBitbucketRefFlag(string arg)
    {
        return arg.Equals("--bitbucket-ref", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-ref=", StringComparison.Ordinal);
    }

    static bool IsBitbucketPullRequestFlag(string arg)
    {
        return arg.Equals("--bitbucket-pull-request", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-pull-request=", StringComparison.Ordinal);
    }

    static bool IsBitbucketIncludeDownloadsFlag(string arg)
    {
        return arg.Equals("--bitbucket-include-downloads", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-include-downloads=", StringComparison.Ordinal);
    }

    static bool IsBitbucketPipelineIdFlag(string arg)
    {
        return arg.Equals("--bitbucket-pipeline-id", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-pipeline-id=", StringComparison.Ordinal);
    }

    static bool IsBitbucketIncludePipelineLogsFlag(string arg)
    {
        return arg.Equals("--bitbucket-include-pipeline-logs", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-include-pipeline-logs=", StringComparison.Ordinal);
    }

    static bool IsBitbucketIncludeSnippetsFlag(string arg)
    {
        return arg.Equals("--bitbucket-include-snippets", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-include-snippets=", StringComparison.Ordinal);
    }

    static bool IsBitbucketTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--bitbucket-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-token-env=", StringComparison.Ordinal);
    }

    static bool IsBitbucketUsernameEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--bitbucket-username-env", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-username-env=", StringComparison.Ordinal);
    }

    static bool IsBitbucketTokenKindFlag(string arg)
    {
        return arg.Equals("--bitbucket-token-kind", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-token-kind=", StringComparison.Ordinal);
    }

    static bool IsBitbucketApiEndpointFlag(string arg)
    {
        return arg.Equals("--bitbucket-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-api-endpoint=", StringComparison.Ordinal);
    }

    static bool TryReadBitbucketCredentialKindFlag(string[] args, ref int index, out BitbucketCredentialKind credentialKind)
    {
        if (!TryReadStringFlag(args, ref index, "--bitbucket-token-kind", out string? value))
        {
            credentialKind = BitbucketCredentialKind.BearerToken;
            return false;
        }

        string normalized = value.Trim().ToLowerInvariant();
        if (normalized is "bearer" or "token" or "api-token")
        {
            credentialKind = BitbucketCredentialKind.BearerToken;
            return true;
        }

        if (normalized is "app-password" or "basic")
        {
            credentialKind = BitbucketCredentialKind.AppPassword;
            return true;
        }

        Console.Error.WriteLine($"unsupported Bitbucket token kind: {value}");
        credentialKind = BitbucketCredentialKind.BearerToken;
        return false;
    }

    static bool TryReadPositiveBitbucketPullRequestFlag(string[] args, ref int index, out int pullRequestId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--bitbucket-pull-request", out pullRequestId))
        {
            return false;
        }

        if (pullRequestId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--bitbucket-pull-request requires a positive integer value");
        return false;
    }

    static bool TryCreateBitbucketSourceProvider(
        Uri? endpoint,
        string repository,
        string workspace,
        string gitRef,
        string projectKey,
        int pullRequestId,
        bool includeDownloads,
        string pipelineId,
        bool includePipelineLogs,
        bool includeSnippets,
        string? tokenEnvironmentVariable,
        string? usernameEnvironmentVariable,
        BitbucketCredentialKind credentialKind,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool hasRepository = !string.IsNullOrWhiteSpace(repository);
        bool hasWorkspace = !string.IsNullOrWhiteSpace(workspace);
        if (hasRepository == hasWorkspace)
        {
            Console.Error.WriteLine("Bitbucket source scan requires exactly one of --bitbucket-repository or --bitbucket-workspace");
            return false;
        }

        if (pullRequestId != 0 && hasWorkspace)
        {
            Console.Error.WriteLine("Bitbucket pull request source scan requires --bitbucket-repository");
            return false;
        }

        if (includeSnippets && !hasWorkspace)
        {
            Console.Error.WriteLine("Bitbucket snippet source scan requires --bitbucket-workspace");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(projectKey) && !hasWorkspace)
        {
            Console.Error.WriteLine("Bitbucket project source scan requires --bitbucket-workspace");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(projectKey) && includeSnippets)
        {
            Console.Error.WriteLine("Bitbucket project source scan cannot be combined with workspace snippet enumeration");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(pipelineId) && !hasRepository)
        {
            Console.Error.WriteLine("Bitbucket pipeline source scan requires --bitbucket-repository");
            return false;
        }

        if (includePipelineLogs && !hasRepository)
        {
            Console.Error.WriteLine("Bitbucket pipeline log source scan requires --bitbucket-repository");
            return false;
        }

        if (pullRequestId != 0 && !string.IsNullOrWhiteSpace(pipelineId))
        {
            Console.Error.WriteLine("Bitbucket source scan cannot combine --bitbucket-pull-request with --bitbucket-pipeline-id");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(pipelineId) && !includePipelineLogs)
        {
            Console.Error.WriteLine("--bitbucket-pipeline-id requires --bitbucket-include-pipeline-logs");
            return false;
        }

        if (includePipelineLogs && string.IsNullOrWhiteSpace(pipelineId))
        {
            Console.Error.WriteLine("--bitbucket-include-pipeline-logs requires --bitbucket-pipeline-id");
            return false;
        }

        if (pullRequestId != 0 && !string.IsNullOrWhiteSpace(gitRef))
        {
            Console.Error.WriteLine("Bitbucket source scan accepts either --bitbucket-ref or --bitbucket-pull-request, not both");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Bitbucket source scan requires --bitbucket-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"Bitbucket token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        string username = string.Empty;
        if (credentialKind == BitbucketCredentialKind.AppPassword)
        {
            if (string.IsNullOrWhiteSpace(usernameEnvironmentVariable))
            {
                Console.Error.WriteLine("Bitbucket app-password source scan requires --bitbucket-username-env");
                return false;
            }

            username = Environment.GetEnvironmentVariable(usernameEnvironmentVariable) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(username))
            {
                Console.Error.WriteLine($"Bitbucket username environment variable is not set: {usernameEnvironmentVariable}");
                return false;
            }

            username = username.Trim();
        }

        Uri sourceEndpoint = endpoint ?? BitbucketSourceOptions.CreateDefaultEndpoint();
        try
        {
            if (hasRepository)
            {
                var validatedOptions = new BitbucketSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    username,
                    credentialKind,
                    gitRef,
                    pullRequestId,
                    includeDownloads,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints,
                    pipelineId: pipelineId,
                    includePipelineLogs: includePipelineLogs);
                sourceEndpoint = validatedOptions.Endpoint;
                repository = validatedOptions.Repository;
                gitRef = validatedOptions.Ref;
                pullRequestId = validatedOptions.PullRequestId;
                includeDownloads = validatedOptions.IncludeDownloads;
                pipelineId = validatedOptions.PipelineId;
                includePipelineLogs = validatedOptions.IncludePipelineLogs;
                credentialKind = validatedOptions.CredentialKind;
            }
            else
            {
                var validatedOptions = new BitbucketWorkspaceSourceOptions(
                    sourceEndpoint,
                    workspace,
                    credential,
                    username,
                    credentialKind,
                    gitRef,
                    projectKey,
                    includeDownloads,
                    includeSnippets,
                    allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
                sourceEndpoint = validatedOptions.Endpoint;
                workspace = validatedOptions.Workspace;
                gitRef = validatedOptions.Ref;
                projectKey = validatedOptions.ProjectKey;
                includeDownloads = validatedOptions.IncludeDownloads;
                includeSnippets = validatedOptions.IncludeSnippets;
                credentialKind = validatedOptions.CredentialKind;
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
            Console.Error.WriteLine($"blocked Bitbucket endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new BitbucketSourceClient(httpClient);
            if (hasRepository)
            {
                return client.EnumerateRepositoryFilesAsync(new BitbucketSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    username,
                    credentialKind,
                    gitRef,
                    pullRequestId,
                    includeDownloads,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    allowInsecureSourceEndpoints,
                    rules.IsGlobalPathAllowed,
                    Console.Error.WriteLine,
                    isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
                    pipelineId: pipelineId,
                    includePipelineLogs: includePipelineLogs), cancellationToken).GetAwaiter().GetResult();
            }

            return client.EnumerateWorkspaceRepositoryFilesAsync(new BitbucketWorkspaceSourceOptions(
                sourceEndpoint,
                workspace,
                credential,
                username,
                credentialKind,
                gitRef,
                projectKey,
                includeDownloads,
                includeSnippets,
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
