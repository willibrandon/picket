using Picket.Engine;
using Picket.Verify;
using System.Diagnostics;
using System.Text.Json;

namespace Picket.Tests;

/// <summary>
/// Tests direct known-secret verification through the built executable.
/// </summary>
[TestClass]
public sealed class CliKnownSecretVerificationTests
{
    private static readonly Uri s_validationCacheEndpoint = new("https://127.0.0.1:1/user");

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that direct-verification help exposes safe secret sources without a secret argument.
    /// </summary>
    /// <param name="arguments">The command tokens used to request direct-verification help.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow(new[] { "verify", "secret", "--help" })]
    [DataRow(new[] { "verify", "--timeout", "30", "secret", "--help" })]
    public async Task VerifySecretHelpDescribesSafeInputs(string[] arguments)
    {
        CliResult result = await RunCliAsync(
            standardInput: null,
            environment: null,
            arguments).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.Contains("--rule-id <id>", result.Stdout);
        Assert.Contains("--provider <provider>", result.Stdout);
        Assert.Contains("--secret-env <name>", result.Stdout);
        Assert.Contains("instead of standard input", result.Stdout);
        Assert.DoesNotContain("<secret>", result.Stdout);
        Assert.DoesNotContain("Arguments:", result.Stdout);
    }

    /// <summary>
    /// Verifies that options placed before the direct-verification subcommand are forwarded in their original order.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretSupportsOptionsBeforeSubcommand()
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubPat();
        const string RuleId = "github-pat";
        string cachePath = Path.Combine(root.Path, "cache");
        WriteValidationCache(cachePath, RuleId, token, SecretValidationState.Active);

        CliResult result = await RunCliAsync(
            token,
            environment: null,
            "verify",
            "--cache-dir",
            cachePath,
            "--timeout",
            "30",
            "secret",
            "--rule-id",
            RuleId,
            "--github-api-endpoint",
            s_validationCacheEndpoint.AbsoluteUri,
            "--allow-non-public-endpoints").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("active", document.RootElement.GetProperty("state").GetString());
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that standard input can select a cached active result without disclosing the credential.
    /// </summary>
    /// <param name="lineEnding">The optional terminal line ending written after the credential.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("")]
    [DataRow("\n")]
    [DataRow("\r")]
    [DataRow("\r\n")]
    public async Task VerifySecretReadsStandardInputWithoutEchoingIt(string lineEnding)
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubPat();
        const string RuleId = "github-pat";
        string cachePath = Path.Combine(root.Path, "cache");
        WriteValidationCache(cachePath, RuleId, token, SecretValidationState.Active);

        CliResult result = await RunCliAsync(
            string.Concat(token, lineEnding),
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            RuleId,
            "--cache-dir",
            cachePath,
            "--github-api-endpoint",
            s_validationCacheEndpoint.AbsoluteUri,
            "--allow-non-public-endpoints",
            "--live-max-requests",
            "1",
            "--live-max-requests-per-provider",
            "1").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        JsonElement rootElement = document.RootElement;
        Assert.AreEqual("picket.validation.v1", rootElement.GetProperty("schema").GetString());
        Assert.AreEqual("active", rootElement.GetProperty("state").GetString());
        Assert.AreEqual("github", rootElement.GetProperty("provider").GetString());
        Assert.AreEqual(RuleId, rootElement.GetProperty("ruleId").GetString());
        Assert.AreEqual("GitHub accepted the token", rootElement.GetProperty("reason").GetString());
        Assert.AreEqual("octocat", rootElement.GetProperty("identity").GetString());
        string[] scopes =
        [
            .. rootElement
            .GetProperty("scopes")
            .EnumerateArray()
            .Select(static value => value.GetString() ?? string.Empty),
        ];
        string[] resources =
        [
            .. rootElement
            .GetProperty("reachableResources")
            .EnumerateArray()
            .Select(static value => value.GetString() ?? string.Empty),
        ];
        string[] evidence =
        [
            .. rootElement
            .GetProperty("evidence")
            .EnumerateArray()
            .Select(static value => value.GetString() ?? string.Empty),
        ];
        Assert.Contains("repo", scopes);
        Assert.Contains("github:user", resources);
        Assert.Contains("fixture=cache", evidence);
        Assert.Contains("cacheHit=persistent", evidence);
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that provider selection infers a supported rule for an environment-sourced credential.
    /// </summary>
    /// <param name="prefix">The GitHub credential prefix.</param>
    /// <param name="suffixLength">The required credential suffix length.</param>
    /// <param name="ruleId">The expected Picket rule identifier.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("github_pat_", 82, "picket-github-fine-grained-personal-access-token")]
    [DataRow("ghu_", 36, "picket-github-app-token")]
    [DataRow("ghs_", 36, "picket-github-app-token")]
    [DataRow("gho_", 36, "picket-github-oauth-token")]
    [DataRow("ghp_", 36, "picket-github-personal-access-token")]
    [DataRow("ghr_", 36, "picket-github-refresh-token")]
    public async Task VerifySecretInfersGitHubRuleFromEnvironmentValue(
        string prefix,
        int suffixLength,
        string ruleId)
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubCredential(prefix, suffixLength);
        const string EnvironmentVariable = "PICKET_DIRECT_VERIFICATION_TEST_SECRET";
        string cachePath = Path.Combine(root.Path, "cache");
        WriteValidationCache(cachePath, ruleId, token, SecretValidationState.Active);
        var environment = new Dictionary<string, string?>
        {
            [EnvironmentVariable] = token,
        };

        CliResult result = await RunCliAsync(
            standardInput: null,
            environment,
            "verify",
            "secret",
            "--provider",
            "github",
            "--secret-env",
            EnvironmentVariable,
            "--cache-dir",
            cachePath,
            "--github-api-endpoint",
            s_validationCacheEndpoint.AbsoluteUri,
            "--allow-non-public-endpoints").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual(ruleId, document.RootElement.GetProperty("ruleId").GetString());
        Assert.AreEqual("active", document.RootElement.GetProperty("state").GetString());
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that a provider-rejected credential uses the finding exit code without disclosure.
    /// </summary>
    /// <param name="state">The terminal validation state read from cache.</param>
    /// <param name="reportValue">The expected stable report value.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow(SecretValidationState.Inactive, "inactive")]
    [DataRow(SecretValidationState.Invalid, "invalid")]
    [DataRow(SecretValidationState.TestCredential, "test-credential")]
    public async Task VerifySecretReturnsFindingExitCodeForRejectedCredential(
        SecretValidationState state,
        string reportValue)
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubPat();
        const string RuleId = "github-pat";
        string cachePath = Path.Combine(root.Path, "cache");
        WriteValidationCache(cachePath, RuleId, token, state);

        CliResult result = await RunCliAsync(
            token,
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            RuleId,
            "--cache-dir",
            cachePath,
            "--github-api-endpoint",
            s_validationCacheEndpoint.AbsoluteUri,
            "--allow-non-public-endpoints").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode, result.Stderr);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual(reportValue, document.RootElement.GetProperty("state").GetString());
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that an unsupported explicit rule returns a secret-free indeterminate result.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretReturnsIndeterminateExitCodeForUnsupportedRule()
    {
        string token = CreateGitHubPat();

        CliResult result = await RunCliAsync(
            token,
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            "unsupported-rule").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("skipped", document.RootElement.GetProperty("state").GetString());
        Assert.Contains(
            "no live validator supports the finding",
            document.RootElement.GetProperty("reason").GetString() ?? string.Empty);
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that direct verification requires one unambiguous selector.
    /// </summary>
    /// <param name="arguments">Selector arguments supplied to the command.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow(new string[] { })]
    [DataRow(new[] { "--rule-id", "github-pat", "--provider", "github" })]
    public async Task VerifySecretRequiresExactlyOneSelector(string[] arguments)
    {
        string token = CreateGitHubPat();
        var command = new List<string> { "verify", "secret" };
        command.AddRange(arguments);

        CliResult result = await RunCliAsync(
            token,
            environment: null,
            [.. command]).ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.Contains("specify exactly one of --rule-id or --provider", result.Stderr);
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that unsupported provider syntax fails locally without echoing the input.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretRejectsUnsupportedProviderSyntax()
    {
        const string Secret = "not-a-supported-provider-secret";

        CliResult result = await RunCliAsync(
            Secret,
            environment: null,
            "verify",
            "secret",
            "--provider",
            "github").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("credential syntax is not supported", result.Stderr);
        Assert.DoesNotContain(Secret, result.Stderr);
    }

    /// <summary>
    /// Verifies that a missing environment credential is reported by name without a secret value.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretReportsMissingEnvironmentVariable()
    {
        const string EnvironmentVariable = "PICKET_UNSET_DIRECT_VERIFICATION_SECRET";
        var environment = new Dictionary<string, string?>
        {
            [EnvironmentVariable] = null,
        };

        CliResult result = await RunCliAsync(
            standardInput: null,
            environment,
            "verify",
            "secret",
            "--provider",
            "github",
            "--secret-env",
            EnvironmentVariable).ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains(EnvironmentVariable, result.Stderr);
    }

    /// <summary>
    /// Verifies that direct verification explains how to provide a credential when standard input is empty.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretRequiresStandardInputOrEnvironmentVariable()
    {
        CliResult result = await RunCliAsync(
            standardInput: null,
            environment: null,
            "verify",
            "secret",
            "--provider",
            "github").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("pipe one through standard input or use --secret-env <name>", result.Stderr);
    }

    /// <summary>
    /// Verifies that endpoint policy failures produce a secret-free indeterminate result.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretAppliesEndpointGuard()
    {
        string token = CreateGitHubPat();

        CliResult result = await RunCliAsync(
            token,
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            "github-pat",
            "--github-api-endpoint",
            "https://metadata.google.internal/user").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("error", document.RootElement.GetProperty("state").GetString());
        Assert.Contains("endpoint blocked", document.RootElement.GetProperty("reason").GetString() ?? string.Empty);
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that direct verification bounds standard-input credential material.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretRejectsOversizedStandardInput()
    {
        string secret = new('x', 65_537);

        CliResult result = await RunCliAsync(
            secret,
            environment: null,
            "verify",
            "secret",
            "--provider",
            "github").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("65536 character secret limit", result.Stderr);
        Assert.DoesNotContain(secret, result.Stderr);
    }

    /// <summary>
    /// Verifies that standard-input normalization removes one terminal line ending without trimming credential data.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretRemovesOnlyOneTrailingLineEnding()
    {
        string token = CreateGitHubPat();

        CliResult result = await RunCliAsync(
            string.Concat(token, "\n\n"),
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            "github-pat").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("skipped", document.RootElement.GetProperty("state").GetString());
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain(token, result.Stderr);
    }

    /// <summary>
    /// Verifies that direct verification bounds environment-sourced credential material.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretRejectsOversizedEnvironmentValue()
    {
        const string EnvironmentVariable = "PICKET_OVERSIZED_DIRECT_VERIFICATION_SECRET";
        string secret = new('x', 65_537);
        var environment = new Dictionary<string, string?>
        {
            [EnvironmentVariable] = secret,
        };

        CliResult result = await RunCliAsync(
            standardInput: null,
            environment,
            "verify",
            "secret",
            "--provider",
            "github",
            "--secret-env",
            EnvironmentVariable).ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("65536 character limit", result.Stderr);
        Assert.Contains(EnvironmentVariable, result.Stderr);
        Assert.DoesNotContain(secret, result.Stderr);
    }

    /// <summary>
    /// Verifies that the documented maximum credential length is accepted.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerifySecretAcceptsMaximumLengthStandardInput()
    {
        string secret = new('x', 65_536);

        CliResult result = await RunCliAsync(
            secret,
            environment: null,
            "verify",
            "secret",
            "--rule-id",
            "unsupported-rule").ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("skipped", document.RootElement.GetProperty("state").GetString());
        Assert.DoesNotContain(secret, result.Stdout);
        Assert.DoesNotContain(secret, result.Stderr);
    }

    private static string CreateGitHubPat()
    {
        return CreateGitHubCredential("ghp_", 36);
    }

    private static string CreateGitHubCredential(string prefix, int suffixLength)
    {
        return string.Concat(prefix, new string('A', suffixLength));
    }

    private static void WriteValidationCache(
        string cachePath,
        string ruleId,
        string token,
        SecretValidationState state)
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        options.UserEndpoint = s_validationCacheEndpoint;
        SecretValidationCache cache = SecretValidationCache.Open(
            Path.Combine(cachePath, "validation"),
            string.Concat(
                "rules:direct:",
                ruleId,
                ";github:",
                options.UserEndpoint,
                ";github-proxy:",
                string.Empty,
                ";github-tls:",
                options.TlsMode.ToString()));
        Finding finding = CreateFinding(ruleId, token);
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "github-rest-user-v1",
            finding,
            options.UserEndpoint);
        cache.Write(
            key,
            new SecretValidationResult(
                state,
                state == SecretValidationState.Active
                    ? "GitHub accepted the token"
                    : "GitHub rejected the token",
                state == SecretValidationState.Active ? "octocat" : string.Empty,
                ["repo"],
                ["github:user"],
                ["fixture=cache"]),
            DateTimeOffset.UtcNow.AddHours(1));
    }

    private static Finding CreateFinding(string ruleId, string token)
    {
        return new Finding(
            ruleId,
            "Direct secret verification",
            1,
            1,
            1,
            token.Length,
            token,
            token,
            "known-secret",
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

    private async Task<CliResult> RunCliAsync(
        string? standardInput,
        IReadOnlyDictionary<string, string?>? environment,
        params string[] arguments)
    {
        string repositoryRoot = GetRepositoryRoot();
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(
            CliExecutablePath.Resolve(repositoryRoot, GetBuildConfiguration()))
        {
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = repositoryRoot,
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG");
        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG_TOML");
        process.StartInfo.Environment.Remove("PICKET_CONFIG");
        process.StartInfo.Environment.Remove("PICKET_CONFIG_TOML");
        if (environment is not null)
        {
            foreach (KeyValuePair<string, string?> variable in environment)
            {
                if (variable.Value is null)
                {
                    process.StartInfo.Environment.Remove(variable.Key);
                }
                else
                {
                    process.StartInfo.Environment[variable.Key] = variable.Value;
                }
            }
        }

        process.Start();
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(TestContext.CancellationToken);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(TestContext.CancellationToken);
        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput.AsMemory(), TestContext.CancellationToken).ConfigureAwait(false);
            process.StandardInput.Close();
        }

        await process.WaitForExitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        return new CliResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));
    }

    private static string GetBuildConfiguration()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            var info = new DirectoryInfo(directory);
            if (info.Parent?.Name.Equals("bin", StringComparison.Ordinal) == true)
            {
                return info.Name;
            }

            directory = info.Parent?.FullName;
        }

        return "Debug";
    }

    private static string GetRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "Picket.slnx")))
        {
            directory = Directory.GetParent(directory)?.FullName;
        }

        return directory ?? throw new InvalidOperationException("Could not locate the repository root.");
    }
}
