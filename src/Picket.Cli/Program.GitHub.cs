using Picket.Engine;
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

    static bool IsGitHubRepositoryTypeFlag(string arg)
    {
        return arg.Equals("--github-repository-type", StringComparison.Ordinal)
            || arg.StartsWith("--github-repository-type=", StringComparison.Ordinal);
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
        string organization,
        string repositoryType,
        string? tokenEnvironmentVariable,
        string gitRef,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out Func<string, CompiledRuleSet, long?, long, List<SourceFile>>? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool repositorySpecified = !string.IsNullOrWhiteSpace(repository);
        bool organizationSpecified = !string.IsNullOrWhiteSpace(organization);
        if (repositorySpecified == organizationSpecified)
        {
            Console.Error.WriteLine("GitHub source scan requires exactly one of --github-repository or --github-organization");
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
                    gitRef);
                sourceEndpoint = validatedOptions.Endpoint;
                repository = validatedOptions.Repository;
                gitRef = validatedOptions.Ref;
            }
            else
            {
                var validatedOptions = new GitHubOrganizationSourceOptions(
                    sourceEndpoint,
                    organization,
                    credential,
                    gitRef,
                    repositoryType);
                sourceEndpoint = validatedOptions.Endpoint;
                organization = validatedOptions.Organization;
                repositoryType = validatedOptions.RepositoryType;
                gitRef = validatedOptions.Ref;
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

        sourceFileProvider = (_, _, maxTargetBytes, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
            });
            var client = new GitHubSourceClient(httpClient);
            if (repositorySpecified)
            {
                return client.EnumerateRepositoryFilesAsync(new GitHubSourceOptions(
                    sourceEndpoint,
                    repository,
                    credential,
                    gitRef,
                    maxTargetBytes,
                    Console.Error.WriteLine,
                    () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
            }

            return client.EnumerateOrganizationRepositoryFilesAsync(new GitHubOrganizationSourceOptions(
                sourceEndpoint,
                organization,
                credential,
                gitRef,
                repositoryType,
                maxTargetBytes,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
