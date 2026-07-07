using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests committed compatibility oracle fixtures.
/// </summary>
[TestClass]
public sealed class CompatibilityOracleFixtureTests
{
    private static readonly string[] s_compatibilityReportFormats = ["json", "csv", "junit", "sarif"];

    /// <summary>
    /// Verifies that the basic directory fixture still matches promoted Gitleaks oracle reports.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task BasicDirectoryReportsMatchPromotedGitleaksOracles()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "basic-dir-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "basic-dir-json");

        foreach (string format in s_compatibilityReportFormats)
        {
            string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", format);
            string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", format);
            using TempDirectory output = TempDirectory.Create();
            string reportPath = Path.Combine(output.Path, $"report.{format}");

            Assert.AreEqual(expectedReport, promotedPicketReport);

            CliResult result = await RunCliFromDirectoryAsync(
                inputRoot,
                "dir",
                ".",
                "-c",
                ".gitleaks.toml",
                "-f",
                format,
                "-r",
                reportPath,
                "--no-banner",
                "--no-color",
                "--redact=100").ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.IsEmpty(result.Stdout);
            Assert.IsEmpty(result.Stderr);
            Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
        }
    }

    /// <summary>
    /// Verifies that the stdin JSON fixture still matches the promoted Gitleaks oracle report.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task StdinJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "stdin-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "stdin-json");
        string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", "json");
        string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", "json");
        string standardInput = File.ReadAllText(Path.Combine(inputRoot, "input.txt"));
        using TempDirectory output = TempDirectory.Create();
        string reportPath = Path.Combine(output.Path, "report.json");

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            inputRoot,
            standardInput,
            "stdin",
            "-c",
            ".gitleaks.toml",
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color",
            "--redact=100").ConfigureAwait(false);

        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    /// <summary>
    /// Verifies that the git JSON fixture still matches the promoted Gitleaks oracle report.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task GitJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "git-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "git-json");
        string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", "json");
        string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", "json");
        using TempDirectory gitRepository = TempDirectory.Create();
        using TempDirectory output = TempDirectory.Create();
        string reportPath = Path.Combine(output.Path, "report.json");

        await CreateGitOracleRepositoryAsync(inputRoot, gitRepository.Path).ConfigureAwait(false);

        CliResult result = await RunCliFromDirectoryAsync(
            gitRepository.Path,
            "git",
            gitRepository.Path,
            "-c",
            Path.Combine(inputRoot, ".gitleaks.toml"),
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color",
            "--redact=100").ConfigureAwait(false);

        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    /// <summary>
    /// Verifies that the baseline JSON fixture still matches the promoted Gitleaks oracle report.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task BaselineJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "baseline-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "baseline-json");
        string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", "json");
        string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", "json");
        using TempDirectory output = TempDirectory.Create();
        string reportPath = Path.Combine(output.Path, "report.json");

        CliResult result = await RunCliFromDirectoryAsync(
            inputRoot,
            "dir",
            ".",
            "-c",
            ".gitleaks.toml",
            "--baseline-path",
            "baseline.json",
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color",
            "--redact=100").ConfigureAwait(false);

        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    private static async Task<CliResult> RunCliFromDirectoryAsync(string workingDirectory, params string[] arguments)
    {
        return await RunCliWithInputFromDirectoryAsync(workingDirectory, standardInput: null, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputFromDirectoryAsync(string workingDirectory, string? standardInput, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
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

    private static async Task CreateGitOracleRepositoryAsync(string inputRoot, string repositoryPath)
    {
        await RunGitCommandAsync(repositoryPath, null, "init", "--object-format=sha1").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "commit.gpgsign", "false").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "i18n.commitEncoding", "utf-8").ConfigureAwait(false);

        string sourceText = NormalizeLineEndings(File.ReadAllText(Path.Combine(inputRoot, "source.txt")));
        File.WriteAllText(Path.Combine(repositoryPath, "source.txt"), sourceText, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        await RunGitCommandAsync(repositoryPath, null, "add", "source.txt").ConfigureAwait(false);
        var environment = new Dictionary<string, string?>
        {
            ["GIT_AUTHOR_NAME"] = "Picket Oracle",
            ["GIT_AUTHOR_EMAIL"] = "picket@example.com",
            ["GIT_AUTHOR_DATE"] = "1704067200 +0000",
            ["GIT_COMMITTER_NAME"] = "Picket Oracle",
            ["GIT_COMMITTER_EMAIL"] = "picket@example.com",
            ["GIT_COMMITTER_DATE"] = "1704067200 +0000",
        };
        await RunGitCommandAsync(repositoryPath, environment, "commit", "--no-gpg-sign", "--no-verify", "-m", "add git oracle secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(repositoryPath, null, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        Assert.AreEqual("a0f75bb7be6981e97ea40bfd4402a58f0e356401", commit);
    }

    private static async Task<string> RunGitCommandAsync(
        string workingDirectory,
        IReadOnlyDictionary<string, string?>? environment,
        params string[] arguments)
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
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Assert.Fail($"git {string.Join(' ', arguments)} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    private static string NormalizeLineEndings(string value)
    {
        return value.ReplaceLineEndings("\n");
    }

    private static string ReadOracleReport(string oracleRoot, string tool, string format)
    {
        return NormalizeLineEndings(File.ReadAllText(Path.Combine(oracleRoot, $"{tool}.{format}")));
    }
}
