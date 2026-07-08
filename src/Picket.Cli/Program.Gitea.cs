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
        string gitRef,
        int pullRequestId,
        bool includeIssues,
        string issueState,
        string? tokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(repository))
        {
            Console.Error.WriteLine("Gitea source scan requires --gitea-repository");
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
            var validatedOptions = new GiteaSourceOptions(
                sourceEndpoint,
                repository,
                credential,
                gitRef,
                includeIssues,
                issueState,
                pullRequestId: pullRequestId,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            repository = validatedOptions.Repository;
            gitRef = validatedOptions.Ref;
            includeIssues = validatedOptions.IncludeIssues;
            issueState = validatedOptions.IssueState;
            pullRequestId = validatedOptions.PullRequestId;
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

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new GiteaSourceClient(httpClient);
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
                isCancellationRequested: () => IsTimedOut(timeoutTimestamp),
                pullRequestId: pullRequestId)).GetAwaiter().GetResult();
        };
        return true;
    }
}
