using Picket.Rules;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests coding-agent prompt and tool-input guards through the built executable.
/// </summary>
[TestClass]
public sealed class CliCodingAgentGuardTests
{
    private const int DefaultMaxInputBytes = 1_000_000;
    private const string InputError = "Picket blocked the coding-agent request because the hook input could not be safely inspected.";
    private const string LimitError = "Picket blocked the coding-agent request because the hook input exceeded the configured limit.";
    private const string RulesError = "Picket blocked the coding-agent request because scanner rules could not be loaded.";

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that command help documents the bounded, local hook contract.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardHelpDocumentsBoundedLocalInput()
    {
        CliResult rootResult = await RunCliAsync(null, "--help").ConfigureAwait(false);
        CliResult guardResult = await RunCliAsync(null, "agent", "guard", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, rootResult.ExitCode, rootResult.Stderr);
        Assert.Contains("agent", rootResult.Stdout);
        Assert.AreEqual(0, guardResult.ExitCode, guardResult.Stderr);
        Assert.Contains("Codex or Claude hook event", guardResult.Stdout);
        Assert.Contains("--config <path>", guardResult.Stdout);
        Assert.Contains("--max-input-megabytes <n>", guardResult.Stdout);
        Assert.Contains("default is 1", guardResult.Stdout);
        Assert.Contains("maximum is 64", guardResult.Stdout);
        Assert.DoesNotContain("--live", guardResult.Stdout);
        Assert.DoesNotContain("--verify", guardResult.Stdout);
        Assert.DoesNotContain("--proxy", guardResult.Stdout);
        Assert.DoesNotContain("--token", guardResult.Stdout);
        Assert.DoesNotContain("--report", guardResult.Stdout);
    }

    /// <summary>
    /// Verifies that clean Codex and Claude hook events continue without output.
    /// </summary>
    /// <param name="envelope">The provider-specific hook envelope.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("""{"hook_event_name":"UserPromptSubmit","prompt":"Review this method.","model":"gpt-5","turn_id":"turn-1"}""")]
    [DataRow("""{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"Update the method name."},"turn_id":"turn-1"}""")]
    [DataRow("""{"hook_event_name":"UserPromptSubmit","prompt":"Review this method.","permission_mode":"default","session_id":"session-1"}""")]
    [DataRow("""{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"src/App.cs","content":"internal class App {}"},"session_id":"session-1"}""")]
    public async Task AgentGuardAllowsCleanCodexAndClaudeEvents(string envelope)
    {
        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that a secret in a submitted prompt blocks both supported provider shapes.
    /// </summary>
    /// <param name="providerProperty">The provider-specific metadata property.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("\"model\":\"gpt-5\"")]
    [DataRow("\"permission_mode\":\"default\"")]
    public async Task AgentGuardBlocksCodexAndClaudePrompts(string providerProperty)
    {
        string secret = CreateGitHubPat();
        string envelope = $$"""{"hook_event_name":"UserPromptSubmit","prompt":"{{secret}}",{{providerProperty}}}""";

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        AssertBlockedFinding(result, secret);
    }

    /// <summary>
    /// Verifies that every nested string value in tool input is inspected.
    /// </summary>
    /// <param name="toolInput">The tool input with a secret placeholder.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("""{"command":"__SECRET__"}""")]
    [DataRow("""{"nested":{"content":"__SECRET__"}}""")]
    [DataRow("""{"items":[{"value":"clean"},"__SECRET__"]}""")]
    public async Task AgentGuardScansEveryNestedToolInputString(string toolInput)
    {
        string secret = CreateGitHubPat();
        string envelope = $$"""{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{toolInput.Replace("__SECRET__", secret, StringComparison.Ordinal)}}}""";

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        AssertBlockedFinding(result, secret);
    }

    /// <summary>
    /// Verifies that hook metadata does not become scanned content.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardDoesNotScanEnvelopeMetadata()
    {
        string secret = CreateGitHubPat();
        string envelope = string.Concat(
            "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"",
            secret,
            "\",\"transcript_path\":\"",
            secret,
            "\",\"cwd\":\"",
            secret,
            "\",\"tool_input\":{\"command\":\"echo clean\"}}");

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that malformed, ambiguous, and unsupported envelopes fail closed.
    /// </summary>
    /// <param name="envelope">The invalid hook envelope.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow("")]
    [DataRow(" ")]
    [DataRow("{")]
    [DataRow("[]")]
    [DataRow("""{"prompt":"clean"}""")]
    [DataRow("""{"hook_event_name":"PostToolUse","tool_input":{"command":"clean"}}""")]
    [DataRow("""{"hook_event_name":"UserPromptSubmit"}""")]
    [DataRow("""{"hook_event_name":"UserPromptSubmit","prompt":1}""")]
    [DataRow("""{"hook_event_name":"PreToolUse"}""")]
    [DataRow("""{"hook_event_name":"UserPromptSubmit","hook_event_name":"PreToolUse","prompt":"clean","tool_input":{}}""")]
    [DataRow("""{"hook_event_name":"UserPromptSubmit","prompt":"clean","prompt":"clean"}""")]
    public async Task AgentGuardRejectsMalformedOrUnsupportedEnvelope(string envelope)
    {
        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        AssertFailClosed(result, InputError);
    }

    /// <summary>
    /// Verifies that an envelope at the default byte limit is inspected.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardAcceptsInputAtDefaultByteLimit()
    {
        const string Prefix = "{\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"";
        const string Suffix = "\"}";
        int contentLength = DefaultMaxInputBytes - Encoding.UTF8.GetByteCount(Prefix) - Encoding.UTF8.GetByteCount(Suffix);
        string envelope = string.Concat(Prefix, new string('x', contentLength), Suffix);
        Assert.AreEqual(DefaultMaxInputBytes, Encoding.UTF8.GetByteCount(envelope));

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that an envelope above the default byte limit is rejected before parsing.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardRejectsInputAboveDefaultByteLimit()
    {
        string input = new('x', DefaultMaxInputBytes + 1);

        CliResult result = await RunCliAsync(input, "agent", "guard").ConfigureAwait(false);

        AssertFailClosed(result, LimitError);
    }

    /// <summary>
    /// Verifies that operators can raise the byte limit within the hard ceiling.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardHonorsConfiguredInputLimit()
    {
        const string Prefix = "{\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"";
        const string Suffix = "\"}";
        int contentLength = DefaultMaxInputBytes + 1 - Encoding.UTF8.GetByteCount(Prefix) - Encoding.UTF8.GetByteCount(Suffix);
        string envelope = string.Concat(Prefix, new string('x', contentLength), Suffix);

        CliResult result = await RunCliAsync(
            envelope,
            "agent",
            "guard",
            "--max-input-megabytes",
            "2").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that the documented maximum input option and built-in rule-pack option are accepted.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardAcceptsMaximumInputLimitAndBuiltInRulePack()
    {
        const string Envelope = """{"hook_event_name":"UserPromptSubmit","prompt":"clean"}""";

        CliResult result = await RunCliAsync(
            Envelope,
            "agent",
            "guard",
            "--max-input-megabytes",
            "64",
            "--rule-pack",
            PicketRulePackNames.Strict).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that a custom configuration replaces the native defaults for guard scans.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardUsesCustomConfiguration()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "guard.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "custom-agent-token"
            regex = '''custom-agent-token-[0-9]+'''
            """);
        const string Envelope = """{"hook_event_name":"UserPromptSubmit","prompt":"custom-agent-token-12345"}""";

        CliResult result = await RunCliAsync(
            Envelope,
            "agent",
            "guard",
            "--config",
            configPath).ConfigureAwait(false);

        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("custom-agent-token", result.Stderr);
        Assert.DoesNotContain("custom-agent-token-12345", result.Stderr);
        Assert.Contains("Secret values are not printed.", result.Stderr);
    }

    /// <summary>
    /// Verifies that option and rule-loading failures use the blocking exit code and fixed output.
    /// </summary>
    /// <param name="arguments">The invalid guard arguments.</param>
    /// <param name="expectedError">The expected fixed error.</param>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    [DataRow(new[] { "agent", "guard", "--unknown" }, InputError)]
    [DataRow(new[] { "agent", "guard", "--max-input-megabytes", "0" }, InputError)]
    [DataRow(new[] { "agent", "guard", "--max-input-megabytes", "65" }, InputError)]
    [DataRow(new[] { "agent", "guard", "--config", "missing-sensitive-name.toml" }, RulesError)]
    public async Task AgentGuardFailsClosedForInvalidOptionsOrRules(string[] arguments, string expectedError)
    {
        const string Envelope = """{"hook_event_name":"UserPromptSubmit","prompt":"clean"}""";

        CliResult result = await RunCliAsync(Envelope, arguments).ConfigureAwait(false);

        AssertFailClosed(result, expectedError);
        Assert.DoesNotContain("missing-sensitive-name.toml", result.Stderr);
    }

    /// <summary>
    /// Verifies that excessive JSON nesting and text fragmentation fail closed.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardRejectsExcessiveDepthOrTextFragmentation()
    {
        string deepEnvelope = string.Concat(
            """{"hook_event_name":"PreToolUse","tool_input":""",
            new string('[', 65),
            "\"clean\"",
            new string(']', 65),
            "}");
        string fragmentedEnvelope = string.Concat(
            "{\"hook_event_name\":\"PreToolUse\",\"tool_input\":[\"",
            string.Join("\",\"", Enumerable.Repeat("x", 4_097)),
            "\"]}");

        CliResult deepResult = await RunCliAsync(deepEnvelope, "agent", "guard").ConfigureAwait(false);
        CliResult fragmentedResult = await RunCliAsync(fragmentedEnvelope, "agent", "guard").ConfigureAwait(false);

        AssertFailClosed(deepResult, InputError);
        AssertFailClosed(fragmentedResult, InputError);
    }

    /// <summary>
    /// Verifies that the documented text-fragment boundary remains accepted.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardAcceptsTextFragmentationAtLimit()
    {
        string envelope = string.Concat(
            "{\"hook_event_name\":\"PreToolUse\",\"tool_input\":[\"",
            string.Join("\",\"", Enumerable.Repeat("x", 4_096)),
            "\"]}");

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that malformed input cannot echo secret material in the blocking diagnostic.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task AgentGuardRedactsMalformedInputDiagnostic()
    {
        string secret = CreateGitHubPat();
        string envelope = string.Concat(
            "{\"hook_event_name\":\"UserPromptSubmit\",\"prompt\":\"",
            secret);

        CliResult result = await RunCliAsync(envelope, "agent", "guard").ConfigureAwait(false);

        AssertFailClosed(result, InputError);
        Assert.DoesNotContain(secret, result.Stderr);
    }

    private static string CreateGitHubPat()
    {
        return string.Concat(
            "ghp_",
            Convert.ToHexString(RandomNumberGenerator.GetBytes(18)).ToLowerInvariant());
    }

    private static void AssertBlockedFinding(CliResult result, string secret)
    {
        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Picket blocked the coding-agent request: 1 secret finding.", result.Stderr);
        Assert.Contains("picket-github-personal-access-token", result.Stderr);
        Assert.Contains("Secret values are not printed.", result.Stderr);
        Assert.DoesNotContain(secret, result.Stdout);
        Assert.DoesNotContain(secret, result.Stderr);
    }

    private static void AssertFailClosed(CliResult result, string expectedError)
    {
        Assert.AreEqual(2, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.AreEqual(string.Concat(expectedError, Environment.NewLine), result.Stderr);
    }

    private async Task<CliResult> RunCliAsync(string? standardInput, params string[] arguments)
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
