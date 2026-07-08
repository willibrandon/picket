using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsGcsBucketFlag(string arg)
    {
        return arg.Equals("--gcs-bucket", StringComparison.Ordinal)
            || arg.StartsWith("--gcs-bucket=", StringComparison.Ordinal);
    }

    static bool IsGcsEndpointFlag(string arg)
    {
        return arg.Equals("--gcs-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--gcs-endpoint=", StringComparison.Ordinal);
    }

    static bool IsGcsPrefixFlag(string arg)
    {
        return arg.Equals("--gcs-prefix", StringComparison.Ordinal)
            || arg.StartsWith("--gcs-prefix=", StringComparison.Ordinal);
    }

    static bool IsGcsTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--gcs-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--gcs-token-env=", StringComparison.Ordinal);
    }

    static bool IsGcsUserProjectFlag(string arg)
    {
        return arg.Equals("--gcs-user-project", StringComparison.Ordinal)
            || arg.StartsWith("--gcs-user-project=", StringComparison.Ordinal);
    }

    static bool TryCreateGcsSourceProvider(
        Uri? endpoint,
        string bucket,
        string prefix,
        string? tokenEnvironmentVariable,
        string userProject,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(bucket))
        {
            Console.Error.WriteLine("GCS source scan requires --gcs-bucket");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("GCS source scan requires --gcs-token-env");
            return false;
        }

        string? token = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(token))
        {
            Console.Error.WriteLine($"GCS token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        Uri sourceEndpoint;
        try
        {
            sourceEndpoint = endpoint ?? GcsSourceOptions.CreateDefaultEndpoint();
            var validatedOptions = new GcsSourceOptions(
                sourceEndpoint,
                bucket,
                token,
                prefix,
                userProject,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            bucket = validatedOptions.Bucket;
            prefix = validatedOptions.Prefix;
            userProject = validatedOptions.UserProject;
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
            Console.Error.WriteLine($"blocked GCS endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new GcsSourceClient(httpClient);
            return client.EnumerateObjectsAsync(new GcsSourceOptions(
                sourceEndpoint,
                bucket,
                token,
                prefix,
                userProject,
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
