using Picket.Security;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    private const int IndeterminateRevocationExitCode = 2;

    private static async Task<int> RunGitHubRevocationAsync(
        string[] credentialEnvironmentVariables,
        bool confirmRevocation,
        Uri? endpoint,
        Uri? proxyEndpoint,
        int timeoutSeconds,
        bool allowNonPublicEndpoints,
        CancellationToken cancellationToken)
    {
        if (!confirmRevocation)
        {
            Console.Error.WriteLine("GitHub credential revocation is irreversible; pass --confirm-revocation to continue");
            return 1;
        }

        if (!TryReadRevocationCredentials(credentialEnvironmentVariables, out string[] credentials))
        {
            return UnknownFlagExitCode;
        }

        try
        {
            GitHubCredentialRevokerOptions options = GitHubCredentialRevokerOptions.CreateDefault();
            options.EndpointGuardOptions = new EndpointGuardOptions
            {
                AllowNonPublicAddresses = allowNonPublicEndpoints,
            };
            options.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
            try
            {
                if (endpoint is not null)
                {
                    options.CredentialEndpoint = endpoint;
                }

                options.ProxyEndpoint = proxyEndpoint;
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"invalid GitHub revocation endpoint configuration: {ex.Message}");
                return UnknownFlagExitCode;
            }

            using var revoker = new GitHubCredentialRevoker(options);
            CredentialRevocationResult result = await revoker.RevokeAsync(credentials, cancellationToken).ConfigureAwait(false);
            return WriteRevocationResult(result);
        }
        finally
        {
            Array.Clear(credentials);
        }
    }

    private static bool TryReadRevocationCredentials(
        string[] environmentVariables,
        out string[] credentials)
    {
        credentials = [];
        if (environmentVariables.Length == 0)
        {
            Console.Error.WriteLine("at least one --credential-env value is required");
            return false;
        }

        if (environmentVariables.Length > 1_000)
        {
            Console.Error.WriteLine("GitHub accepts at most 1000 credentials per revocation request");
            return false;
        }

        var values = new string[environmentVariables.Length];
        for (int i = 0; i < environmentVariables.Length; i++)
        {
            string variable = environmentVariables[i];
            if (string.IsNullOrWhiteSpace(variable))
            {
                Console.Error.WriteLine("--credential-env values cannot be empty");
                Array.Clear(values);
                return false;
            }

            string? value = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrEmpty(value))
            {
                Console.Error.WriteLine($"credential environment variable is not set or empty: {variable}");
                Array.Clear(values);
                return false;
            }

            values[i] = value;
        }

        credentials = values;
        return true;
    }

    private static int WriteRevocationResult(CredentialRevocationResult result)
    {
        switch (result.State)
        {
            case CredentialRevocationState.Accepted:
                Console.Out.WriteLine($"GitHub accepted {result.CredentialCount} credential(s) for revocation.");
                return 0;
            case CredentialRevocationState.Rejected:
                Console.Error.WriteLine($"revocation rejected: {result.Reason}");
                return 1;
            case CredentialRevocationState.Indeterminate:
                Console.Error.WriteLine($"revocation outcome is indeterminate: {result.Reason}");
                return IndeterminateRevocationExitCode;
            case CredentialRevocationState.Blocked:
                Console.Error.WriteLine($"revocation blocked: {result.Reason}");
                return 1;
            default:
                throw new ArgumentOutOfRangeException(nameof(result));
        }
    }
}
