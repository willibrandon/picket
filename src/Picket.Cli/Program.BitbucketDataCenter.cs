using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsBitbucketDataCenterApiEndpointFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-api-endpoint=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterProjectFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-project", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-project=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterRepositoryFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-repository", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-repository=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterRefFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-ref", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-ref=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterPullRequestFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-pull-request", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-pull-request=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-token-env=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterUsernameEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-username-env", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-username-env=", StringComparison.Ordinal);
    }

    static bool IsBitbucketDataCenterTokenKindFlag(string arg)
    {
        return arg.Equals("--bitbucket-data-center-token-kind", StringComparison.Ordinal)
            || arg.StartsWith("--bitbucket-data-center-token-kind=", StringComparison.Ordinal);
    }

    static bool TryReadBitbucketDataCenterCredentialKindFlag(
        string[] args,
        ref int index,
        out BitbucketDataCenterCredentialKind credentialKind)
    {
        if (!TryReadStringFlag(args, ref index, "--bitbucket-data-center-token-kind", out string? value))
        {
            credentialKind = BitbucketDataCenterCredentialKind.BearerToken;
            return false;
        }

        string normalized = value.Trim().ToLowerInvariant();
        if (normalized is "bearer" or "token" or "http-token")
        {
            credentialKind = BitbucketDataCenterCredentialKind.BearerToken;
            return true;
        }

        if (normalized is "basic" or "password")
        {
            credentialKind = BitbucketDataCenterCredentialKind.Basic;
            return true;
        }

        Console.Error.WriteLine($"unsupported Bitbucket Data Center token kind: {value}");
        credentialKind = BitbucketDataCenterCredentialKind.BearerToken;
        return false;
    }

    static bool TryReadPositiveBitbucketDataCenterPullRequestFlag(
        string[] args,
        ref int index,
        out int pullRequestId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--bitbucket-data-center-pull-request", out pullRequestId))
        {
            return false;
        }

        if (pullRequestId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--bitbucket-data-center-pull-request requires a positive integer value");
        return false;
    }

    static bool TryCreateBitbucketDataCenterSourceProvider(
        Uri? endpoint,
        string projectKey,
        string repositorySlug,
        string gitRef,
        int pullRequestId,
        string? tokenEnvironmentVariable,
        string? usernameEnvironmentVariable,
        BitbucketDataCenterCredentialKind credentialKind,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (endpoint is null)
        {
            Console.Error.WriteLine("Bitbucket Data Center source scan requires --bitbucket-data-center-api-endpoint");
            return false;
        }

        if (string.IsNullOrWhiteSpace(projectKey))
        {
            Console.Error.WriteLine("Bitbucket Data Center source scan requires --bitbucket-data-center-project");
            return false;
        }

        if (pullRequestId != 0 && string.IsNullOrWhiteSpace(repositorySlug))
        {
            Console.Error.WriteLine("Bitbucket Data Center pull request scan requires --bitbucket-data-center-repository");
            return false;
        }

        if (pullRequestId != 0 && !string.IsNullOrWhiteSpace(gitRef))
        {
            Console.Error.WriteLine("Bitbucket Data Center source scan accepts either --bitbucket-data-center-ref or --bitbucket-data-center-pull-request, not both");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Bitbucket Data Center source scan requires --bitbucket-data-center-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"Bitbucket Data Center token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        string username = string.Empty;
        if (credentialKind == BitbucketDataCenterCredentialKind.Basic)
        {
            if (string.IsNullOrWhiteSpace(usernameEnvironmentVariable))
            {
                Console.Error.WriteLine("Bitbucket Data Center Basic source scan requires --bitbucket-data-center-username-env");
                return false;
            }

            username = Environment.GetEnvironmentVariable(usernameEnvironmentVariable) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(username))
            {
                Console.Error.WriteLine($"Bitbucket Data Center username environment variable is not set: {usernameEnvironmentVariable}");
                return false;
            }

            username = username.Trim();
        }

        BitbucketDataCenterSourceOptions validatedOptions;
        try
        {
            validatedOptions = new BitbucketDataCenterSourceOptions(
                endpoint,
                projectKey,
                credential,
                repositorySlug,
                username,
                credentialKind,
                gitRef,
                pullRequestId,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
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
        EndpointGuardResult endpointGuardResult = EndpointGuard.Evaluate(validatedOptions.Endpoint, endpointGuardOptions);
        if (!endpointGuardResult.IsAllowed)
        {
            Console.Error.WriteLine($"blocked Bitbucket Data Center endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, rules, maxTargetBytes, _, _, _, _, timeoutTimestamp, cancellationToken) =>
        {
            using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
            {
                EndpointGuardOptions = endpointGuardOptions,
            }), disposeHandler: true);
            var client = new BitbucketDataCenterSourceClient(httpClient);
            return client.EnumerateFilesAsync(new BitbucketDataCenterSourceOptions(
                validatedOptions.Endpoint,
                validatedOptions.ProjectKey,
                credential,
                validatedOptions.RepositorySlug,
                username,
                validatedOptions.CredentialKind,
                validatedOptions.Ref,
                validatedOptions.PullRequestId,
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
