using Picket.Engine;
using Picket.Verify;
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Picket;

internal static partial class Program
{
    private const int MaxDirectSecretCharacters = 64 * 1_024;
    private const string DirectSecretSource = "known-secret";

    private static async Task<int> RunVerifySecretAsync(string[] args, CancellationToken cancellationToken)
    {
        bool allowNonPublicProviderEndpoints = false;
        string? cacheDir = null;
        Uri? githubApiEndpoint = null;
        Uri? githubApiProxyEndpoint = null;
        GitHubSecretLiveValidatorTlsMode? githubApiTlsMode = null;
        int? maxProviderRequests = null;
        int? maxRequestsPerProvider = null;
        TimeSpan? minimumRequestInterval = null;
        TimeSpan? minimumRequestIntervalPerProvider = null;
        string? provider = null;
        string? ruleId = null;
        string? secretEnvironmentVariable = null;
        int timeoutSeconds = 0;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsNamedValueFlag(arg, "--rule-id"))
            {
                if (!TryReadStringFlag(args, ref i, "--rule-id", out ruleId))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsNamedValueFlag(arg, "--provider"))
            {
                if (!TryReadStringFlag(args, ref i, "--provider", out provider))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsNamedValueFlag(arg, "--secret-env"))
            {
                if (!TryReadStringFlag(args, ref i, "--secret-env", out secretEnvironmentVariable))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsCacheDirFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--cache-dir", out cacheDir))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsGitHubApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-endpoint", out githubApiEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsGitHubApiProxyFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-proxy", out githubApiProxyEndpoint))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsLiveTlsModeFlag(arg))
            {
                if (!TryReadLiveTlsModeFlag(args, ref i, out GitHubSecretLiveValidatorTlsMode value))
                {
                    return NativeOperationalExitCode;
                }

                githubApiTlsMode = value;
                continue;
            }

            if (IsLiveRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-rate-limit-ms", out TimeSpan value))
                {
                    return NativeOperationalExitCode;
                }

                minimumRequestInterval = value;
                continue;
            }

            if (IsLiveProviderRateLimitMillisecondsFlag(arg))
            {
                if (!TryReadNonNegativeMillisecondsFlag(args, ref i, "--live-provider-rate-limit-ms", out TimeSpan value))
                {
                    return NativeOperationalExitCode;
                }

                minimumRequestIntervalPerProvider = value;
                continue;
            }

            if (IsLiveMaxRequestsFlag(arg))
            {
                if (!TryReadPositiveIntFlag(args, ref i, "--live-max-requests", out int value))
                {
                    return NativeOperationalExitCode;
                }

                maxProviderRequests = value;
                continue;
            }

            if (IsLiveMaxRequestsPerProviderFlag(arg))
            {
                if (!TryReadPositiveIntFlag(args, ref i, "--live-max-requests-per-provider", out int value))
                {
                    return NativeOperationalExitCode;
                }

                maxRequestsPerProvider = value;
                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            if (IsTimeoutFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
                {
                    return NativeOperationalExitCode;
                }

                continue;
            }

            Console.Error.WriteLine($"unknown flag: {arg}");
            return UnknownFlagExitCode;
        }

        if (!TryValidateDirectSecretSelector(ruleId, provider))
        {
            return NativeOperationalExitCode;
        }

        if (provider is not null && !provider.Equals("github", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("--provider currently supports github");
            return NativeOperationalExitCode;
        }

        string? secret = await ReadDirectSecretAsync(secretEnvironmentVariable, cancellationToken).ConfigureAwait(false);
        if (secret is null)
        {
            return NativeOperationalExitCode;
        }

        ruleId ??= InferGitHubRuleId(secret);
        if (ruleId is null)
        {
            Console.Error.WriteLine("the credential syntax is not supported by the selected provider");
            return NativeOperationalExitCode;
        }

        var configuration = new LiveVerificationConfiguration(
            githubApiEndpoint,
            githubApiProxyEndpoint,
            githubApiTlsMode,
            allowNonPublicProviderEndpoints,
            minimumRequestInterval,
            minimumRequestIntervalPerProvider,
            maxProviderRequests,
            maxRequestsPerProvider);
        if (!TryCreateLiveVerifier(configuration, cacheDir, string.Concat("direct:", ruleId), out SecretLiveVerifier? verifier))
        {
            return NativeOperationalExitCode;
        }

        using (verifier)
        using (CancellationTokenSource? timeout = CreateDirectVerificationCancellation(timeoutSeconds, cancellationToken))
        {
            CancellationToken verificationCancellationToken = timeout?.Token ?? cancellationToken;
            Finding finding = CreateDirectSecretFinding(ruleId, secret);
            SecretValidationResult result;
            try
            {
                result = await verifier.VerifyAsync(finding, verificationCancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                timeout?.IsCancellationRequested == true &&
                !cancellationToken.IsCancellationRequested)
            {
                result = new SecretValidationResult(
                    SecretValidationState.Error,
                    "direct verification timed out",
                    isPersistentCacheable: false);
            }

            WriteDirectValidationResult(ruleId, "github", result);
            return GetDirectValidationExitCode(result.State);
        }
    }

    private static bool IsNamedValueFlag(string argument, string name)
    {
        return argument.Equals(name, StringComparison.Ordinal)
            || argument.StartsWith(string.Concat(name, "="), StringComparison.Ordinal);
    }

    private static bool TryValidateDirectSecretSelector(string? ruleId, string? provider)
    {
        bool hasRule = !string.IsNullOrWhiteSpace(ruleId);
        bool hasProvider = !string.IsNullOrWhiteSpace(provider);
        if (hasRule == hasProvider)
        {
            Console.Error.WriteLine("specify exactly one of --rule-id or --provider");
            return false;
        }

        return true;
    }

    private static async ValueTask<string?> ReadDirectSecretAsync(
        string? environmentVariable,
        CancellationToken cancellationToken)
    {
        if (environmentVariable is not null)
        {
            if (string.IsNullOrWhiteSpace(environmentVariable))
            {
                Console.Error.WriteLine("--secret-env requires a non-empty environment variable name");
                return null;
            }

            string? value = Environment.GetEnvironmentVariable(environmentVariable);
            if (string.IsNullOrEmpty(value))
            {
                Console.Error.WriteLine($"secret environment variable is not set or empty: {environmentVariable}");
                return null;
            }

            if (value.Length > MaxDirectSecretCharacters)
            {
                Console.Error.WriteLine($"secret environment variable exceeds the {MaxDirectSecretCharacters} character limit: {environmentVariable}");
                return null;
            }

            return value;
        }

        if (!Console.IsInputRedirected)
        {
            Console.Error.WriteLine("pipe the secret through standard input or use --secret-env <name>");
            return null;
        }

        char[] buffer = ArrayPool<char>.Shared.Rent(MaxDirectSecretCharacters + 1);
        try
        {
            int length = 0;
            while (length < MaxDirectSecretCharacters + 1)
            {
                int read = await Console.In.ReadAsync(
                    buffer.AsMemory(length, MaxDirectSecretCharacters + 1 - length),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }

            if (length > MaxDirectSecretCharacters)
            {
                Console.Error.WriteLine($"standard input exceeds the {MaxDirectSecretCharacters} character secret limit");
                return null;
            }

            length = RemoveOneTrailingLineEnding(buffer.AsSpan(0, length));
            if (length == 0)
            {
                Console.Error.WriteLine("standard input did not contain a secret; pipe one through standard input or use --secret-env <name>");
                return null;
            }

            return new string(buffer, 0, length);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static int RemoveOneTrailingLineEnding(ReadOnlySpan<char> value)
    {
        if (value.EndsWith("\r\n", StringComparison.Ordinal))
        {
            return value.Length - 2;
        }

        if (value.EndsWith("\n", StringComparison.Ordinal) || value.EndsWith("\r", StringComparison.Ordinal))
        {
            return value.Length - 1;
        }

        return value.Length;
    }

    private static string? InferGitHubRuleId(string secret)
    {
        if (secret.StartsWith("github_pat_", StringComparison.Ordinal))
        {
            return "picket-github-fine-grained-personal-access-token";
        }

        if (secret.StartsWith("ghu_", StringComparison.Ordinal) || secret.StartsWith("ghs_", StringComparison.Ordinal))
        {
            return "picket-github-app-token";
        }

        if (secret.StartsWith("gho_", StringComparison.Ordinal))
        {
            return "picket-github-oauth-token";
        }

        if (secret.StartsWith("ghp_", StringComparison.Ordinal))
        {
            return "picket-github-personal-access-token";
        }

        if (secret.StartsWith("ghr_", StringComparison.Ordinal))
        {
            return "picket-github-refresh-token";
        }

        return null;
    }

    private static Finding CreateDirectSecretFinding(string ruleId, string secret)
    {
        return new Finding(
            ruleId,
            "Direct secret verification",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
            DirectSecretSource,
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            string.Empty);
    }

    private static CancellationTokenSource? CreateDirectVerificationCancellation(
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        if (timeoutSeconds == 0)
        {
            return null;
        }

        CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        return timeout;
    }

    private static void WriteDirectValidationResult(
        string ruleId,
        string provider,
        SecretValidationResult result)
    {
        var output = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", "picket.validation.v1");
            writer.WriteString("state", result.ReportValue);
            writer.WriteString("provider", provider);
            writer.WriteString("ruleId", ruleId);
            writer.WriteString("reason", result.Reason);
            writer.WriteString("identity", result.Identity);
            WriteDirectValidationArray(writer, "scopes", result.Scopes);
            WriteDirectValidationArray(writer, "reachableResources", result.ReachableResources);
            WriteDirectValidationArray(writer, "evidence", result.Evidence);
            writer.WriteEndObject();
        }

        Console.Out.WriteLine(Encoding.UTF8.GetString(output.WrittenSpan));
    }

    private static void WriteDirectValidationArray(
        Utf8JsonWriter writer,
        string propertyName,
        IReadOnlyList<string> values)
    {
        writer.WriteStartArray(propertyName);
        for (int i = 0; i < values.Count; i++)
        {
            writer.WriteStringValue(values[i]);
        }

        writer.WriteEndArray();
    }

    private static int GetDirectValidationExitCode(SecretValidationState state)
    {
        return state switch
        {
            SecretValidationState.Active => 0,
            SecretValidationState.Inactive or
            SecretValidationState.Invalid or
            SecretValidationState.TestCredential => 1,
            _ => NativeOperationalExitCode,
        };
    }
}
