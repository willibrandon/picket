using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests Gitleaks-compatible CLI behavior through the built executable.
/// </summary>
[TestClass]
public sealed class CliCompatibilityTests
{
    /// <summary>
    /// Verifies that --exit-code controls the leak exit code.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanUsesConfiguredExitCode()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--exit-code", "7").ConfigureAwait(false);

        Assert.AreEqual(7, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that -r writes JSON reports to a file instead of standard output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.json");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that -r - writes JSON reports to standard output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesStdoutReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", "-").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that -f csv writes a Gitleaks-compatible CSV report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesCsvReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "csv").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags\n", result.Stdout);
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,12,,,,,secret.txt:token:1,\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that report paths ending in .csv infer CSV when -f is omitted.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanInfersCsvReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.csv");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,12,,,,,secret.txt:token:1,\n", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that -f junit writes a Gitleaks-compatible JUnit report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesJunitReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "junit").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", result.Stdout);
        Assert.Contains("<testsuite failures=\"1\" name=\"gitleaks\" tests=\"1\" time=\"\">", result.Stdout);
        Assert.Contains("<failure message=\"token has detected a secret in file secret.txt, line 1.\" type=\"\">", result.Stdout);
        Assert.Contains("{&#xA;&#x9;&#34;RuleID&#34;: &#34;token&#34;,", result.Stdout);
    }

    /// <summary>
    /// Verifies that -f sarif writes a Gitleaks-compatible SARIF report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesSarifReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "sarif").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\"", result.Stdout);
        Assert.Contains("\"name\": \"gitleaks\"", result.Stdout);
        Assert.Contains("\"ruleId\": \"token\"", result.Stdout);
        Assert.Contains("\"uri\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"text\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that report paths ending in .sarif infer SARIF when -f is omitted.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanInfersSarifReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.sarif");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"ruleId\": \"token\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that inline gitleaks:allow comments suppress CLI findings by default.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanSuppressesInlineGitleaksAllowByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345 // gitleaks:allow");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that --ignore-gitleaks-allow reports otherwise suppressed CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanReportsInlineGitleaksAllowWhenIgnored()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345 // gitleaks:allow");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--ignore-gitleaks-allow").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that skipReport rules suppress normal CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanSuppressesSkipReportRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "supporting-rule"
            regex = '''token-[0-9]+'''
            skipReport = true
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that required supporting rules gate normal CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanReportsCompositeRuleWhenRequiredRuleMatches()
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
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "username=\"alice\"\npassword=\"secret\"");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"primary-rule\"", result.Stdout);
        Assert.Contains("\"Secret\": \"secret\"", result.Stdout);
        Assert.DoesNotContain("\"RuleID\": \"username-rule\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git history scans report committed secrets with commit metadata and fingerprints.
    /// </summary>
    [TestMethod]
    public async Task GitScanReportsCommittedSecret()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.Contains($"\"Commit\": \"{commit}\"", result.Stdout);
        Assert.Contains("\"File\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"Author\": \"Picket Test\"", result.Stdout);
        Assert.Contains("\"Email\": \"picket@example.com\"", result.Stdout);
        Assert.Contains("\"Message\": \"add secret\"", result.Stdout);
        Assert.Contains($"\"Fingerprint\": \"{commit}:secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git scans honor Gitleaks-compatible global fingerprint ignore entries.
    /// </summary>
    [TestMethod]
    public async Task GitScanHonorsGlobalGitleaksIgnoreFingerprint()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, ".gitleaksignore"), "secret.txt:token:1\n");

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that staged git scans report index additions without commit metadata.
    /// </summary>
    [TestMethod]
    public async Task GitScanReportsStagedSecret()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath, "--staged").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"File\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect shim maps to a git history scan by default.
    /// </summary>
    [TestMethod]
    public async Task DetectShimMapsDefaultToGitScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        CliResult result = await RunCliAsync("detect", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains($"\"Commit\": \"{commit}\"", result.Stdout);
        Assert.Contains($"\"Fingerprint\": \"{commit}:secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect --no-git shim maps to a directory scan.
    /// </summary>
    [TestMethod]
    public async Task DetectShimNoGitMapsToDirectoryScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");

        CliResult result = await RunCliAsync("detect", "--no-git", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect --pipe shim maps to stdin scanning.
    /// </summary>
    [TestMethod]
    public async Task DetectShimPipeMapsToStdinScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithInputAsync("token-12345", "detect", "--pipe", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"File\": \"stdin\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"stdin:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated protect shim maps to a pre-commit git diff scan.
    /// </summary>
    [TestMethod]
    public async Task ProtectShimMapsToPreCommitScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "clean\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");

        CliResult result = await RunCliAsync("protect", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the Gitleaks-compatible git platform set is accepted and native auto is rejected.
    /// </summary>
    [TestMethod]
    public async Task GitScanValidatesCompatiblePlatformValues()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);

        CliResult accepted = await RunCliAsync("git", root.Path, "-c", configPath, "--platform", "github").ConfigureAwait(false);
        CliResult rejected = await RunCliAsync("git", root.Path, "-c", configPath, "--platform", "auto").ConfigureAwait(false);

        Assert.AreEqual(1, accepted.ExitCode);
        Assert.AreEqual(126, rejected.ExitCode);
        Assert.Contains("invalid scm platform value: auto", rejected.Stderr);
    }

    private static string WriteTokenConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """);
        return configPath;
    }

    private static async Task InitializeGitRepositoryAsync(string root)
    {
        await RunGitCommandAsync(root, "init").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.name", "Picket Test").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.email", "picket@example.com").ConfigureAwait(false);
    }

    private static async Task<string> RunGitCommandAsync(string workingDirectory, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo("git")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Assert.Fail($"git {string.Join(' ', arguments)} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    private static async Task<CliResult> RunCliAsync(params string[] arguments)
    {
        return await RunCliWithInputAsync(null, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputAsync(string? standardInput, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = GetRepositoryRoot(),
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput).ConfigureAwait(false);
            await process.StandardInput.FlushAsync().ConfigureAwait(false);
            process.StandardInput.Close();
        }

        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
    }

    private static string GetCliExecutablePath()
    {
        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string executablePath = Path.Combine(
            GetRepositoryRoot(),
            "src",
            "Picket.Cli",
            "bin",
            GetBuildConfiguration(),
            "net10.0",
            RuntimeInformation.RuntimeIdentifier,
            executableName);

        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException("Could not locate built picket executable.", executablePath);
        }

        return executablePath;
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

        return directory ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
