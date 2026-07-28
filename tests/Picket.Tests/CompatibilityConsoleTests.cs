using Hex1b;
using Hex1b.Automation;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
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
    /// Verifies an attached Windows console preserves Unicode banner glyphs under a legacy code page.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task WindowsAttachedConsolePreservesUnicodeBanner()
    {
        using TempDirectory root = TempDirectory.Create();
        string scriptPath = Path.Combine(root.Path, "console-test.cmd");
        File.WriteAllText(
            scriptPath,
            $"""
            @echo off
            chcp 437 >nul
            echo harmless | "{GetCliExecutablePath()}" stdin --no-color
            chcp
            pause >nul
            """);

        CancellationToken cancellationToken = TestContext.CancellationToken;
        await using Hex1bTerminal terminal = Hex1bTerminal.CreateBuilder()
            .WithPtyProcess(options =>
            {
                options.FileName = "cmd.exe";
                options.Arguments = ["/d", "/q", "/c", scriptPath];
                options.WorkingDirectory = GetRepositoryRoot();
                options.WindowsPtyMode = WindowsPtyMode.RequireProxy;
                options.WindowsPtyHostPath = GetHex1bPtyHostPath();
            })
            .WithHeadless()
            .WithDimensions(120, 20)
            .Build();

        Task<int> runTask = terminal.RunAsync(cancellationToken);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => s.ContainsText("no leaks found") && s.ContainsText("437"),
                TimeSpan.FromSeconds(15),
                "scan summary and preserved code page")
            .Build()
            .ApplyAsync(terminal, cancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Type("q")
            .Build()
            .ApplyAsync(terminal, cancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        string screenText = snapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("○", screenText);
        Assert.Contains("│╲", screenText);
        Assert.Contains("○ ░", screenText);
        Assert.Contains("░    picket", screenText);
        Assert.Contains("437", screenText);
    }

    /// <summary>
    /// Verifies redirected console streams remain BOM-free UTF-8.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task RedirectedConsoleStreamsUseUtf8WithoutBom()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "unicode.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "unicode-rule"
            description = "Detects the test value."
            regex = '''clé=([^ ]+)'''
            secretGroup = 1
            """);

        (int exitCode, byte[] stdoutBytes, byte[] stderrBytes) = await RunCliWithInputBytesAsync(
            "clé=secret123",
            "stdin",
            "--config",
            configPath,
            "--verbose",
            "--no-color").ConfigureAwait(false);

        var strictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        string stdout = strictUtf8.GetString(stdoutBytes);
        string stderr = strictUtf8.GetString(stderrBytes);

        Assert.AreEqual(1, exitCode);
        Assert.IsNotEmpty(stdout);
        Assert.IsNotEmpty(stderr);
        Assert.AreNotEqual('\uFEFF', stdout[0]);
        Assert.AreNotEqual('\uFEFF', stderr[0]);
        Assert.Contains("Finding:     clé=secret123", stdout);
        Assert.Contains("│╲", stderr);
        Assert.Contains("░    picket", stderr);
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

    private static string GetHex1bPtyHostPath()
    {
        string runtimeIdentifier = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "win-arm64",
            Architecture.X64 => "win-x64",
            _ => throw new PlatformNotSupportedException(
                $"Hex1b PTY tests do not support {RuntimeInformation.ProcessArchitecture}."),
        };
        string path = Path.Combine(AppContext.BaseDirectory, $"hex1bpty-{runtimeIdentifier}.exe");
        return File.Exists(path)
            ? path
            : throw new FileNotFoundException("Could not locate the Hex1b Windows PTY test host.", path);
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

    private async Task<(int ExitCode, byte[] Stdout, byte[] Stderr)> RunCliWithInputBytesAsync(
        string standardInput,
        params string[] arguments)
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

        CancellationToken cancellationToken = TestContext.CancellationToken;
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        Task stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(stdout, cancellationToken);
        Task stderrTask = process.StandardError.BaseStream.CopyToAsync(stderr, cancellationToken);
        await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken).ConfigureAwait(false);
        await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
        process.StandardInput.Close();
        await Task.WhenAll(
            stdoutTask,
            stderrTask,
            process.WaitForExitAsync(cancellationToken)).ConfigureAwait(false);

        return (process.ExitCode, stdout.ToArray(), stderr.ToArray());
    }

    [GeneratedRegex("(?m)^\\d{1,2}:\\d{2}(?:AM|PM)\\s+", RegexOptions.CultureInvariant)]
    private static partial Regex ClockPrefixPattern();

    [GeneratedRegex("(?m)( scanned ~[0-9.,]+ [A-Za-z]+ \\([0-9.,]+ [A-Za-z]+\\) in )\\S+", RegexOptions.CultureInvariant)]
    private static partial Regex ScanDurationPattern();
}
