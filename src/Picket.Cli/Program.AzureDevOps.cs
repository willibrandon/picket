using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsAzureDevOpsOrganizationFlag(string arg)
    {
        return arg.Equals("--azure-devops-organization", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-organization=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsEndpointFlag(string arg)
    {
        return arg.Equals("--azure-devops-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-endpoint=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsTokenEnvironmentVariableFlag(string arg)
    {
        return arg.Equals("--azure-devops-token-env", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-token-env=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsTokenKindFlag(string arg)
    {
        return arg.Equals("--azure-devops-token-kind", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-token-kind=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsProjectFlag(string arg)
    {
        return arg.Equals("--azure-devops-project", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-project=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsRepositoryFlag(string arg)
    {
        return arg.Equals("--azure-devops-repository", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-repository=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsBranchFlag(string arg)
    {
        return arg.Equals("--azure-devops-branch", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-branch=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsPullRequestFlag(string arg)
    {
        return arg.Equals("--azure-devops-pull-request", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-pull-request=", StringComparison.Ordinal);
    }

    static bool IsAzureDevOpsIncludeWikisFlag(string arg)
    {
        return arg.Equals("--azure-devops-include-wikis", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-include-wikis=", StringComparison.Ordinal);
    }

    static bool IsAllowNonPublicSourceEndpointsFlag(string arg)
    {
        return arg.Equals("--allow-non-public-source-endpoints", StringComparison.Ordinal)
            || arg.StartsWith("--allow-non-public-source-endpoints=", StringComparison.Ordinal);
    }

    static bool IsAllowInsecureSourceEndpointsFlag(string arg)
    {
        return arg.Equals("--allow-insecure-source-endpoints", StringComparison.Ordinal)
            || arg.StartsWith("--allow-insecure-source-endpoints=", StringComparison.Ordinal);
    }

    static bool IsUnsupportedAzureDevOpsSourceFlag(string arg)
    {
        return arg.Equals("--azure-devops-include-artifacts", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-include-artifacts=", StringComparison.Ordinal)
            || arg.Equals("--azure-devops-include-logs", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-include-logs=", StringComparison.Ordinal)
            || arg.Equals("--azure-devops-max-artifact-megabytes", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-max-artifact-megabytes=", StringComparison.Ordinal)
            || arg.Equals("--azure-devops-max-log-megabytes", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-max-log-megabytes=", StringComparison.Ordinal);
    }

    static bool TryReadAzureDevOpsCredentialKindFlag(string[] args, ref int index, out AzureDevOpsCredentialKind credentialKind)
    {
        if (!TryReadStringFlag(args, ref index, "--azure-devops-token-kind", out string? value))
        {
            credentialKind = AzureDevOpsCredentialKind.PersonalAccessToken;
            return false;
        }

        string normalized = value.Trim().ToLowerInvariant();
        if (normalized is "pat" or "personal-access-token")
        {
            credentialKind = AzureDevOpsCredentialKind.PersonalAccessToken;
            return true;
        }

        if (normalized is "bearer" or "job-token" or "system-access-token")
        {
            credentialKind = AzureDevOpsCredentialKind.BearerToken;
            return true;
        }

        Console.Error.WriteLine($"unsupported Azure DevOps token kind: {value}");
        credentialKind = AzureDevOpsCredentialKind.PersonalAccessToken;
        return false;
    }

    static bool TryReadPositiveAzureDevOpsPullRequestFlag(string[] args, ref int index, out int pullRequestId)
    {
        if (!TryReadNonNegativeIntFlag(args, ref index, "--azure-devops-pull-request", out pullRequestId))
        {
            return false;
        }

        if (pullRequestId > 0)
        {
            return true;
        }

        Console.Error.WriteLine("--azure-devops-pull-request requires a positive integer value");
        return false;
    }

    static bool TryReadUnsupportedAzureDevOpsSourceFlag(string[] args, ref int index, string arg)
    {
        if (arg.StartsWith("--azure-devops-include-artifacts", StringComparison.Ordinal)
            || arg.StartsWith("--azure-devops-include-logs", StringComparison.Ordinal))
        {
            if (!TryReadBooleanFlag(arg, GetLongFlagName(arg), out bool enabled))
            {
                return false;
            }

            if (!enabled)
            {
                return true;
            }
        }
        else if (!TryReadStringFlag(args, ref index, GetLongFlagName(arg), out _))
        {
            return false;
        }

        Console.Error.WriteLine($"{GetLongFlagName(arg)} is not implemented yet");
        return false;
    }

    static bool TryCreateAzureDevOpsSourceProvider(
        string? organization,
        Uri? endpoint,
        string? tokenEnvironmentVariable,
        AzureDevOpsCredentialKind credentialKind,
        string project,
        string repository,
        string branch,
        int pullRequestId,
        bool includeWikis,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out RemoteSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        if (!string.IsNullOrWhiteSpace(organization) && endpoint is not null)
        {
            Console.Error.WriteLine("Azure DevOps source scan accepts either --azure-devops-organization or --azure-devops-endpoint, not both");
            return false;
        }

        Uri sourceEndpoint;
        try
        {
            if (endpoint is not null)
            {
                sourceEndpoint = endpoint;
            }
            else if (!string.IsNullOrWhiteSpace(organization))
            {
                sourceEndpoint = AzureDevOpsSourceOptions.CreateServicesEndpoint(organization);
            }
            else
            {
                Console.Error.WriteLine("Azure DevOps source scan requires --azure-devops-organization or --azure-devops-endpoint");
                return false;
            }
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Azure DevOps source scan requires --azure-devops-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine($"Azure DevOps token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        try
        {
            var validatedOptions = new AzureDevOpsSourceOptions(
                sourceEndpoint,
                credential,
                credentialKind,
                project,
                repository,
                branch,
                pullRequestId,
                includeWikis);
            sourceEndpoint = validatedOptions.Endpoint;
            project = validatedOptions.Project;
            repository = validatedOptions.Repository;
            branch = validatedOptions.Branch;
            pullRequestId = validatedOptions.PullRequestId;
            includeWikis = validatedOptions.IncludeWikis;
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }

        if (pullRequestId != 0 && branch.Length != 0)
        {
            Console.Error.WriteLine("Azure DevOps source scan accepts either --azure-devops-branch or --azure-devops-pull-request, not both");
            return false;
        }

        if (pullRequestId != 0 && includeWikis)
        {
            Console.Error.WriteLine("Azure DevOps source scan cannot combine --azure-devops-pull-request with --azure-devops-include-wikis");
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
            Console.Error.WriteLine($"blocked Azure DevOps endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (_, _, maxTargetBytes, _, _, _, _, timeoutTimestamp) =>
        {
            using var httpClient = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
            });
            var client = new AzureDevOpsSourceClient(httpClient);
            return client.EnumerateRepositoryFilesAsync(new AzureDevOpsSourceOptions(
                sourceEndpoint,
                credential,
                credentialKind,
                project,
                repository,
                branch,
                pullRequestId,
                includeWikis,
                maxTargetBytes,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp))).GetAwaiter().GetResult();
        };
        return true;
    }

    private static string GetLongFlagName(string arg)
    {
        int equals = arg.IndexOf('=');
        return equals < 0 ? arg : arg[..equals];
    }
}
