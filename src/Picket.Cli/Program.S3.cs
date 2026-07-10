using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsS3BucketFlag(string arg)
    {
        return arg.Equals("--s3-bucket", StringComparison.Ordinal)
            || arg.StartsWith("--s3-bucket=", StringComparison.Ordinal);
    }

    static bool IsS3RegionFlag(string arg)
    {
        return arg.Equals("--s3-region", StringComparison.Ordinal)
            || arg.StartsWith("--s3-region=", StringComparison.Ordinal);
    }

    static bool IsS3EndpointFlag(string arg)
    {
        return arg.Equals("--s3-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--s3-endpoint=", StringComparison.Ordinal);
    }

    static bool IsS3PrefixFlag(string arg)
    {
        return arg.Equals("--s3-prefix", StringComparison.Ordinal)
            || arg.StartsWith("--s3-prefix=", StringComparison.Ordinal);
    }

    static bool IsS3AccessKeyIdEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--s3-access-key-id-env", StringComparison.Ordinal)
            || arg.StartsWith("--s3-access-key-id-env=", StringComparison.Ordinal);
    }

    static bool IsS3SecretAccessKeyEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--s3-secret-access-key-env", StringComparison.Ordinal)
            || arg.StartsWith("--s3-secret-access-key-env=", StringComparison.Ordinal);
    }

    static bool IsS3SessionTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--s3-session-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--s3-session-token-env=", StringComparison.Ordinal);
    }

    static bool TryCreateS3SourceProvider(
        Uri? endpoint,
        string bucket,
        string region,
        string prefix,
        string? accessKeyIdEnvironmentVariable,
        string? secretAccessKeyEnvironmentVariable,
        string? sessionTokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(bucket))
        {
            Console.Error.WriteLine("S3 source scan requires --s3-bucket");
            return false;
        }

        if (string.IsNullOrWhiteSpace(region))
        {
            Console.Error.WriteLine("S3 source scan requires --s3-region");
            return false;
        }

        if (string.IsNullOrWhiteSpace(accessKeyIdEnvironmentVariable))
        {
            Console.Error.WriteLine("S3 source scan requires --s3-access-key-id-env");
            return false;
        }

        if (string.IsNullOrWhiteSpace(secretAccessKeyEnvironmentVariable))
        {
            Console.Error.WriteLine("S3 source scan requires --s3-secret-access-key-env");
            return false;
        }

        string? accessKeyId = Environment.GetEnvironmentVariable(accessKeyIdEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(accessKeyId))
        {
            Console.Error.WriteLine($"S3 access key ID environment variable is not set: {accessKeyIdEnvironmentVariable}");
            return false;
        }

        string? secretAccessKey = Environment.GetEnvironmentVariable(secretAccessKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(secretAccessKey))
        {
            Console.Error.WriteLine($"S3 secret access key environment variable is not set: {secretAccessKeyEnvironmentVariable}");
            return false;
        }

        string sessionToken = string.Empty;
        if (!string.IsNullOrWhiteSpace(sessionTokenEnvironmentVariable))
        {
            sessionToken = Environment.GetEnvironmentVariable(sessionTokenEnvironmentVariable) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(sessionToken))
            {
                Console.Error.WriteLine($"S3 session token environment variable is not set: {sessionTokenEnvironmentVariable}");
                return false;
            }
        }

        Uri sourceEndpoint;
        try
        {
            sourceEndpoint = endpoint ?? S3SourceOptions.CreateDefaultEndpoint(region);
            var validatedOptions = new S3SourceOptions(
                sourceEndpoint,
                bucket,
                region,
                accessKeyId,
                secretAccessKey,
                sessionToken,
                prefix,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            bucket = validatedOptions.Bucket;
            region = validatedOptions.Region;
            accessKeyId = validatedOptions.AccessKeyId;
            sessionToken = validatedOptions.SessionToken;
            prefix = validatedOptions.Prefix;
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
            Console.Error.WriteLine($"blocked S3 endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new S3SourceClient(httpClient);
            return client.EnumerateObjectsAsync(new S3SourceOptions(
                sourceEndpoint,
                bucket,
                region,
                accessKeyId,
                secretAccessKey,
                sessionToken,
                prefix,
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                cancellationToken).GetAwaiter().GetResult();
        };
        return true;
    }
}
