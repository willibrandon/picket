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

    static bool IsGitLabRefFlag(string arg)
    {
        return arg.Equals("--gitlab-ref", StringComparison.Ordinal)
            || arg.StartsWith("--gitlab-ref=", StringComparison.Ordinal);
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

    static bool TryCreateGitLabSourceProvider(
        Uri? endpoint,
        string project,
        string gitRef,
        string? tokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(project))
        {
            Console.Error.WriteLine("GitLab source scan requires --gitlab-project");
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
            var validatedOptions = new GitLabSourceOptions(
                sourceEndpoint,
                project,
                credential,
                gitRef);
            sourceEndpoint = validatedOptions.Endpoint;
            project = validatedOptions.Project;
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
            Console.Error.WriteLine($"blocked GitLab endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
            });
            var client = new GitLabSourceClient(httpClient);
            return client.EnumerateRepositoryFilesAsync(new GitLabSourceOptions(
                sourceEndpoint,
                project,
                credential,
                gitRef,
                maxTargetBytes,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
