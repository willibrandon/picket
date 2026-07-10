using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsRegistryImageFlag(string arg)
    {
        return arg.Equals("--registry-image", StringComparison.Ordinal)
            || arg.StartsWith("--registry-image=", StringComparison.Ordinal);
    }

    static bool IsRegistryEndpointFlag(string arg)
    {
        return arg.Equals("--registry-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--registry-endpoint=", StringComparison.Ordinal);
    }

    static bool IsRegistryAuthenticationEndpointFlag(string arg)
    {
        return arg.Equals("--registry-auth-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--registry-auth-endpoint=", StringComparison.Ordinal);
    }

    static bool IsRegistryTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--registry-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--registry-token-env=", StringComparison.Ordinal);
    }

    static bool IsRegistryUsernameEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--registry-username-env", StringComparison.Ordinal)
            || arg.StartsWith("--registry-username-env=", StringComparison.Ordinal);
    }

    static bool IsRegistryPasswordEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--registry-password-env", StringComparison.Ordinal)
            || arg.StartsWith("--registry-password-env=", StringComparison.Ordinal);
    }

    static bool IsRegistryPlatformFlag(string arg)
    {
        return arg.Equals("--registry-platform", StringComparison.Ordinal)
            || arg.StartsWith("--registry-platform=", StringComparison.Ordinal);
    }

    static bool IsRegistryMaxImageMegabytesFlag(string arg)
    {
        return arg.Equals("--registry-max-image-megabytes", StringComparison.Ordinal)
            || arg.StartsWith("--registry-max-image-megabytes=", StringComparison.Ordinal);
    }

    static bool TryCreateContainerRegistrySourceProvider(
        string imageValue,
        Uri? endpoint,
        Uri? authenticationEndpoint,
        string? tokenEnvironmentVariable,
        string? usernameEnvironmentVariable,
        string? passwordEnvironmentVariable,
        string platform,
        long? maxImageBytes,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(imageValue))
        {
            Console.Error.WriteLine("container registry source scan requires --registry-image");
            return false;
        }

        if (tokenEnvironmentVariable is not null && string.IsNullOrWhiteSpace(tokenEnvironmentVariable)
            || usernameEnvironmentVariable is not null && string.IsNullOrWhiteSpace(usernameEnvironmentVariable)
            || passwordEnvironmentVariable is not null && string.IsNullOrWhiteSpace(passwordEnvironmentVariable))
        {
            Console.Error.WriteLine("container registry credential environment variable names must not be empty");
            return false;
        }

        bool bearerConfigured = tokenEnvironmentVariable is not null;
        bool usernameConfigured = usernameEnvironmentVariable is not null;
        bool passwordConfigured = passwordEnvironmentVariable is not null;
        if (bearerConfigured && (usernameConfigured || passwordConfigured)
            || usernameConfigured != passwordConfigured)
        {
            Console.Error.WriteLine("container registry authentication accepts either --registry-token-env or both --registry-username-env and --registry-password-env");
            return false;
        }

        ContainerRegistryCredentialKind credentialKind = ContainerRegistryCredentialKind.Anonymous;
        string credential = string.Empty;
        string username = string.Empty;
        if (bearerConfigured)
        {
            credentialKind = ContainerRegistryCredentialKind.BearerToken;
            if (!TryReadEnvironmentCredential(tokenEnvironmentVariable!, "container registry token", out credential))
            {
                return false;
            }
        }
        else if (usernameConfigured)
        {
            credentialKind = ContainerRegistryCredentialKind.Basic;
            if (!TryReadEnvironmentCredential(usernameEnvironmentVariable!, "container registry username", out username)
                || !TryReadEnvironmentCredential(passwordEnvironmentVariable!, "container registry password", out credential))
            {
                return false;
            }
        }

        ContainerRegistryImageReference image;
        Uri sourceEndpoint;
        try
        {
            image = ContainerRegistryImageReference.Parse(imageValue);
            var validatedOptions = new ContainerRegistrySourceOptions(
                image,
                endpoint,
                credentialKind,
                credential,
                username,
                authenticationEndpoint,
                platform,
                maxImageBytes: maxImageBytes,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            authenticationEndpoint = validatedOptions.AuthenticationEndpoint;
            platform = validatedOptions.Platform;
            maxImageBytes = validatedOptions.MaxImageBytes;
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
        EndpointGuardResult endpointResult = EndpointGuard.Evaluate(sourceEndpoint, endpointGuardOptions);
        if (!endpointResult.IsAllowed)
        {
            Console.Error.WriteLine($"blocked container registry endpoint: {endpointResult.Message}");
            return false;
        }

        if (authenticationEndpoint is not null)
        {
            EndpointGuardResult authenticationResult = EndpointGuard.Evaluate(authenticationEndpoint, endpointGuardOptions);
            if (!authenticationResult.IsAllowed)
            {
                Console.Error.WriteLine($"blocked container registry authentication endpoint: {authenticationResult.Message}");
                return false;
            }
        }

        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new ContainerRegistrySourceClient(httpClient);
            return client.EnumerateImageFilesAsync(new ContainerRegistrySourceOptions(
                image,
                sourceEndpoint,
                credentialKind,
                credential,
                username,
                authenticationEndpoint,
                platform,
                maxTargetBytes,
                maxImageBytes,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                cancellationToken).GetAwaiter().GetResult();
        };
        return true;
    }

    private static bool TryReadEnvironmentCredential(
        string environmentVariable,
        string description,
        out string value)
    {
        if (!IsPortableEnvironmentVariableName(environmentVariable))
        {
            value = string.Empty;
            Console.Error.WriteLine($"{description} environment variable name is invalid: {environmentVariable}");
            return false;
        }

        value = Environment.GetEnvironmentVariable(environmentVariable) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            Console.Error.WriteLine($"{description} environment variable is not set: {environmentVariable}");
            return false;
        }

        return true;
    }

    private static bool IsPortableEnvironmentVariableName(string value)
    {
        if (value.Length == 0 || value[0] is not ('_' or >= 'A' and <= 'Z' or >= 'a' and <= 'z'))
        {
            return false;
        }

        foreach (char character in value.AsSpan(1))
        {
            if (character is not ('_' or >= '0' and <= '9' or >= 'A' and <= 'Z' or >= 'a' and <= 'z'))
            {
                return false;
            }
        }

        return true;
    }
}
