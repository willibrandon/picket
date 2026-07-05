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

    private static async Task<CliResult> RunCliAsync(params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = GetRepositoryRoot(),
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
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
