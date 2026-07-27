using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Picket.Tests;

/// <summary>
/// Tests the Gitleaks-compatible console output contract.
/// </summary>
[TestClass]
public sealed partial class CompatibilityConsoleTests
{
    private static readonly string s_gitHubToken = CreateGitHubToken();
    private static readonly string s_verboseFinding = $"""
        Finding:     {s_gitHubToken}
        Secret:      {s_gitHubToken}
        RuleID:      github-pat
        Entropy:     5.021928


        """;

    /// <summary>
    /// Gets or sets the current test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies verbose stdin output and scan summaries match the compatibility contract.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task StdinVerboseOutputMatchesGitleaksContract()
    {
        CliResult result = await RunCliWithInputAsync(
            s_gitHubToken,
            "stdin",
            "--verbose",
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.AreEqual(s_verboseFinding, result.Stdout.ReplaceLineEndings("\n"));
        Assert.AreEqual(
            """
            <time> INF scanned ~40 bytes (40 bytes) in <duration>
            <time> WRN leaks found: 1

            """,
            NormalizeStderr(result.Stderr));
    }

    /// <summary>
    /// Verifies redirected ANSI output matches the Gitleaks compatibility contract.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task StdinVerboseRedirectedColorMatchesGitleaksContract()
    {
        CliResult result = await RunCliWithInputAsync(
            s_gitHubToken,
            "stdin",
            "--verbose",
            "--no-banner").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.AreEqual(
            s_verboseFinding.Replace(
                s_gitHubToken,
                $"\u001b[1;3;m{s_gitHubToken}\u001b[0m",
                StringComparison.Ordinal),
            result.Stdout.ReplaceLineEndings("\n"));
        Assert.Contains("\u001b[90m", result.Stderr);
        Assert.Contains("\u001b[33mWRN\u001b[0m", result.Stderr);
    }

    /// <summary>
    /// Verifies recursive compatibility options work before the command name.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompatibilityOptionsCanPrecedeCommand()
    {
        CliResult result = await RunCliWithInputAsync(
            s_gitHubToken,
            "--verbose",
            "--no-banner",
            "--no-color",
            "stdin").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.AreEqual(s_verboseFinding, result.Stdout.ReplaceLineEndings("\n"));
        Assert.Contains("WRN leaks found: 1", result.Stderr);
    }

    /// <summary>
    /// Verifies warning and error log levels suppress lower-severity records.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompatibilityLogLevelFiltersSummaryRecords()
    {
        CliResult warning = await RunCliWithInputAsync(
            s_gitHubToken,
            "--log-level",
            "warn",
            "--no-banner",
            "--no-color",
            "stdin").ConfigureAwait(false);
        CliResult error = await RunCliWithInputAsync(
            s_gitHubToken,
            "--log-level",
            "error",
            "--no-banner",
            "--no-color",
            "stdin").ConfigureAwait(false);

        Assert.AreEqual(1, warning.ExitCode);
        Assert.AreEqual("<time> WRN leaks found: 1\n", NormalizeStderr(warning.Stderr));
        Assert.AreEqual(1, error.ExitCode);
        Assert.IsEmpty(error.Stderr);
    }

    /// <summary>
    /// Verifies short compatibility options accept equals-delimited values.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompatibilityShortOptionsAcceptEqualsValues()
    {
        CliResult warning = await RunCliWithInputAsync(
            s_gitHubToken,
            "-l=warn",
            "--no-banner",
            "--no-color",
            "stdin").ConfigureAwait(false);
        CliResult nonVerbose = await RunCliWithInputAsync(
            s_gitHubToken,
            "-v=false",
            "--no-banner",
            "--no-color",
            "stdin").ConfigureAwait(false);

        Assert.AreEqual(1, warning.ExitCode);
        Assert.AreEqual("<time> WRN leaks found: 1\n", NormalizeStderr(warning.Stderr));
        Assert.AreEqual(1, nonVerbose.ExitCode);
        Assert.IsEmpty(nonVerbose.Stdout);
        Assert.Contains("WRN leaks found: 1", nonVerbose.Stderr);
    }

    /// <summary>
    /// Verifies redaction is applied before verbose finding output is written.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task StdinVerboseOutputHonorsRedaction()
    {
        CliResult result = await RunCliWithInputAsync(
            s_gitHubToken,
            "stdin",
            "--verbose",
            "--redact=100",
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Finding:     REDACTED", result.Stdout);
        Assert.Contains("Secret:      REDACTED", result.Stdout);
        Assert.DoesNotContain(s_gitHubToken, result.Stdout);
    }

    /// <summary>
    /// Verifies a clean stdin scan writes the informational summary only.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CleanStdinScanWritesNoLeaksSummary()
    {
        CliResult result = await RunCliWithInputAsync(
            "harmless",
            "stdin",
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.AreEqual(
            """
            <time> INF scanned ~8 bytes (8 bytes) in <duration>
            <time> INF no leaks found

            """,
            NormalizeStderr(result.Stderr));
    }

    /// <summary>
    /// Verifies the compatibility banner identifies Picket.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompatibilityBannerIdentifiesPicket()
    {
        CliResult result = await RunCliWithInputAsync("harmless", "--no-color", "stdin").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("░    picket", result.Stderr);
        Assert.DoesNotContain("gitleaks", result.Stderr);
    }

    /// <summary>
    /// Verifies verbose composite findings identify the supporting rule evidence.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task VerboseCompositeFindingIncludesRequiredEvidence()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "primary-rule"
            regex = '''password="([^"]+)"'''

            [[rules.required]]
            id = "username-rule"

            [[rules]]
            id = "username-rule"
            regex = '''username="([^"]+)"'''
            skipReport = true
            """);

        CliResult result = await RunCliWithInputAsync(
            "username=\"alice\"\npassword=\"secret\"",
            "stdin",
            "--config",
            configPath,
            "--verbose",
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Required:    username-rule:1:alice", result.Stdout);
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

    private static string GetCliExecutablePath()
    {
        return CliExecutablePath.Resolve(GetRepositoryRoot(), GetBuildConfiguration());
    }

    private static string GetRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "Picket.slnx")))
        {
            directory = Directory.GetParent(directory)?.FullName;
        }

        return directory ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private static string NormalizeStderr(string value)
    {
        string normalized = value.ReplaceLineEndings("\n");
        normalized = ClockPrefixPattern().Replace(normalized, "<time> ");
        return ScanDurationPattern().Replace(normalized, "$1<duration>");
    }

    private static string CreateGitHubToken()
    {
        char[] suffix = "By6kR01wuAHcoHO5ZsqtKhdEs1VYMngiFSB2".ToCharArray();
        Array.Reverse(suffix);
        return string.Concat("ghp_", suffix);
    }

    private async Task<CliResult> RunCliWithInputAsync(string standardInput, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = GetRepositoryRoot(),
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
        await process.StandardInput.WriteAsync(standardInput).ConfigureAwait(false);
        await process.StandardInput.FlushAsync().ConfigureAwait(false);
        process.StandardInput.Close();

        CancellationToken cancellationToken = TestContext.CancellationToken;
        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
    }

    [GeneratedRegex("(?m)^\\d{1,2}:\\d{2}(?:AM|PM)\\s+", RegexOptions.CultureInvariant)]
    private static partial Regex ClockPrefixPattern();

    [GeneratedRegex("(?m)( scanned ~[0-9.,]+ [A-Za-z]+ \\([0-9.,]+ [A-Za-z]+\\) in )\\S+", RegexOptions.CultureInvariant)]
    private static partial Regex ScanDurationPattern();
}
