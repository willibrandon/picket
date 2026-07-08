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

    static bool TryCreateGiteaSourceProvider(
        Uri? endpoint,
        string repository,
        string gitRef,
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
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
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
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
