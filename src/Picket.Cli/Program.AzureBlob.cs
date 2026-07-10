using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsAzureBlobEndpointFlag(string arg)
    {
        return arg.Equals("--azure-blob-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--azure-blob-endpoint=", StringComparison.Ordinal);
    }

    static bool IsAzureBlobContainerFlag(string arg)
    {
        return arg.Equals("--azure-blob-container", StringComparison.Ordinal)
            || arg.StartsWith("--azure-blob-container=", StringComparison.Ordinal);
    }

    static bool IsAzureBlobPrefixFlag(string arg)
    {
        return arg.Equals("--azure-blob-prefix", StringComparison.Ordinal)
            || arg.StartsWith("--azure-blob-prefix=", StringComparison.Ordinal);
    }

    static bool IsAzureBlobTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--azure-blob-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--azure-blob-token-env=", StringComparison.Ordinal);
    }

    static bool IsAzureBlobTokenKindFlag(string arg)
    {
        return arg.Equals("--azure-blob-token-kind", StringComparison.Ordinal)
            || arg.StartsWith("--azure-blob-token-kind=", StringComparison.Ordinal);
    }

    static bool TryReadAzureBlobCredentialKindFlag(string[] args, ref int index, out AzureBlobCredentialKind credentialKind)
    {
        if (!TryReadStringFlag(args, ref index, "--azure-blob-token-kind", out string? value))
        {
            credentialKind = AzureBlobCredentialKind.BearerToken;
            return false;
        }

        string normalized = value.Trim().ToLowerInvariant();
        if (normalized is "bearer" or "bearer-token" or "entra" or "azure-ad")
        {
            credentialKind = AzureBlobCredentialKind.BearerToken;
            return true;
        }

        if (normalized is "sas" or "shared-access-signature")
        {
            credentialKind = AzureBlobCredentialKind.SharedAccessSignature;
            return true;
        }

        Console.Error.WriteLine($"unsupported Azure Blob token kind: {value}");
        credentialKind = AzureBlobCredentialKind.BearerToken;
        return false;
    }

    static bool TryCreateAzureBlobSourceProvider(
        Uri? endpoint,
        string container,
        string prefix,
        string? tokenEnvironmentVariable,
        AzureBlobCredentialKind credentialKind,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (endpoint is null)
        {
            Console.Error.WriteLine("Azure Blob source scan requires --azure-blob-endpoint");
            return false;
        }

        if (string.IsNullOrWhiteSpace(container))
        {
            Console.Error.WriteLine("Azure Blob source scan requires --azure-blob-container");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Azure Blob source scan requires --azure-blob-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"Azure Blob token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        Uri sourceEndpoint = endpoint;
        try
        {
            var validatedOptions = new AzureBlobSourceOptions(
                sourceEndpoint,
                container,
                credential,
                credentialKind,
                prefix,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            container = validatedOptions.Container;
            prefix = validatedOptions.Prefix;
            credentialKind = validatedOptions.CredentialKind;
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
            Console.Error.WriteLine($"blocked Azure Blob endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new AzureBlobSourceClient(httpClient);
            return client.EnumerateBlobsAsync(new AzureBlobSourceOptions(
                sourceEndpoint,
                container,
                credential,
                credentialKind,
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
