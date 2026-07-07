using System.Diagnostics.CodeAnalysis;
using Picket.Engine;
using Picket.Security;
using Picket.Sources;

namespace Picket;

internal static partial class Program
{
    static bool IsGitHubRepositoryFlag(string arg)
    {
        return arg.Equals("--github-repository", StringComparison.Ordinal)
            || arg.StartsWith("--github-repository=", StringComparison.Ordinal);
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

    static bool IsGitHubSourceApiEndpointFlag(string arg)
    {
        return arg.Equals("--github-source-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--github-source-api-endpoint=", StringComparison.Ordinal);
    }

    static bool TryCreateGitHubSourceProvider(
        Uri? endpoint,
        string repository,
        string? tokenEnvironmentVariable,
        string gitRef,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out Func<string, CompiledRuleSet, long?, long, List<SourceFile>>? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(repository))
        {
            Console.Error.WriteLine("GitHub source scan requires --github-repository");
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
            var validatedOptions = new GitHubSourceOptions(
                sourceEndpoint,
                repository,
                credential,
                gitRef);
            sourceEndpoint = validatedOptions.Endpoint;
            repository = validatedOptions.Repository;
            gitRef = validatedOptions.Ref;
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

        sourceFileProvider = (_, _, maxTargetBytes, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
            });
            var client = new GitHubSourceClient(httpClient);
            return client.EnumerateRepositoryFilesAsync(new GitHubSourceOptions(
                sourceEndpoint,
                repository,
                credential,
                gitRef,
                maxTargetBytes,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
