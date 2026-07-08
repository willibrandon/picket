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
        string gitRef,
        int pullRequestId,
        string? tokenEnvironmentVariable,
        string? usernameEnvironmentVariable,
        BitbucketCredentialKind credentialKind,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (string.IsNullOrWhiteSpace(repository))
        {
            Console.Error.WriteLine("Bitbucket source scan requires --bitbucket-repository");
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
            var validatedOptions = new BitbucketSourceOptions(
                sourceEndpoint,
                repository,
                credential,
                username,
                credentialKind,
                gitRef,
                pullRequestId,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            repository = validatedOptions.Repository;
            gitRef = validatedOptions.Ref;
            pullRequestId = validatedOptions.PullRequestId;
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
            Console.Error.WriteLine($"blocked Bitbucket endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new BitbucketSourceClient(httpClient);
            return client.EnumerateRepositoryFilesAsync(new BitbucketSourceOptions(
                sourceEndpoint,
                repository,
                credential,
                username,
                credentialKind,
                gitRef,
                pullRequestId,
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }
}
