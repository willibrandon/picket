using System.Diagnostics;
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
    /// Verifies that provider-specific findings take precedence over generic findings like Gitleaks.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task GenericPrecedenceJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "generic-precedence-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "generic-precedence-json");
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
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    /// <summary>
    /// Verifies Go's ASCII Perl classes and Unicode controls match the promoted Gitleaks oracle.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task GoRegexAsciiClassesJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "go-regex-ascii-classes-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "go-regex-ascii-classes-json");
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
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
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

    /// <summary>
    /// Verifies that JSON reports escape HTML-sensitive characters like Gitleaks.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task HtmlSensitiveJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "html-escape-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "html-escape-json");
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
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color").ConfigureAwait(false);

        Assert.Contains("oracle\\u003csecret\\u003e\\u002612345", expectedReport);
        Assert.DoesNotContain("oracle<secret>&12345", expectedReport);
        Assert.AreEqual(expectedReport, promotedPicketReport);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    /// <summary>
    /// Verifies custom template output still matches the promoted Gitleaks oracle.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task TemplateReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "template-dir");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "template-dir");
        string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", "template");
        string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", "template");
        using TempDirectory output = TempDirectory.Create();
        string reportPath = Path.Combine(output.Path, "report.txt");

        CliResult result = await RunCliFromDirectoryAsync(
            inputRoot,
            "dir",
            ".",
            "-c",
            ".gitleaks.toml",
            "-f",
            "template",
            "-r",
            reportPath,
            "--report-template",
            "report.tmpl",
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
    /// Verifies every built-in compatibility writer preserves Gitleaks' empty-report bytes.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task EmptyReportsMatchPromotedGitleaksOracles()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "empty-dir-reports");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "empty-dir-reports");

        foreach (string format in s_compatibilityReportFormats)
        {
            string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", format);
            string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", format);
            using TempDirectory output = TempDirectory.Create();
            string reportPath = Path.Combine(output.Path, $"report.{format}");

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
                "--no-color").ConfigureAwait(false);

            Assert.AreEqual(expectedReport, promotedPicketReport);
            Assert.AreEqual(0, result.ExitCode);
            Assert.IsEmpty(result.Stdout);
            Assert.IsEmpty(result.Stderr);
            Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
        }
    }

    /// <summary>
    /// Verifies multi-commit additions and a renamed path match promoted Gitleaks reports.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task MultiCommitGitReportsMatchPromotedGitleaksOracles()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "git-multicommit-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "git-multicommit");
        using TempDirectory gitRepository = TempDirectory.Create();

        await CreateMultiCommitGitOracleRepositoryAsync(inputRoot, gitRepository.Path).ConfigureAwait(false);

        foreach (string format in s_compatibilityReportFormats)
        {
            string expectedReport = ReadOracleReport(oracleRoot, "gitleaks", format);
            string promotedPicketReport = ReadOracleReport(oracleRoot, "picket", format);
            using TempDirectory output = TempDirectory.Create();
            string reportPath = Path.Combine(output.Path, $"report.{format}");

            CliResult result = await RunCliFromDirectoryAsync(
                gitRepository.Path,
                "git",
                gitRepository.Path,
                "-c",
                Path.Combine(inputRoot, ".gitleaks.toml"),
                "-f",
                format,
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
        return CliExecutablePath.Resolve(GetRepositoryRoot(), GetBuildConfiguration());
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

    private static async Task CreateMultiCommitGitOracleRepositoryAsync(string inputRoot, string repositoryPath)
    {
        await RunGitCommandAsync(repositoryPath, null, "init", "--object-format=sha1").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "commit.gpgsign", "false").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "diff.renames", "true").ConfigureAwait(false);
        await RunGitCommandAsync(repositoryPath, null, "config", "i18n.commitEncoding", "utf-8").ConfigureAwait(false);

        string firstText = NormalizeLineEndings(File.ReadAllText(Path.Combine(inputRoot, "first.txt")));
        File.WriteAllText(Path.Combine(repositoryPath, "first.txt"), firstText, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        await RunGitCommandAsync(repositoryPath, null, "add", "first.txt").ConfigureAwait(false);
        Dictionary<string, string?> environment = CreateGitOracleEnvironment("1704067200 +0000");
        await RunGitCommandAsync(repositoryPath, environment, "commit", "--no-gpg-sign", "--no-verify", "-m", "add historical oracle secret").ConfigureAwait(false);

        await RunGitCommandAsync(repositoryPath, null, "mv", "first.txt", "renamed.txt").ConfigureAwait(false);
        environment = CreateGitOracleEnvironment("1704153600 +0000");
        await RunGitCommandAsync(repositoryPath, environment, "commit", "--no-gpg-sign", "--no-verify", "-m", "rename oracle source").ConfigureAwait(false);

        string secondText = NormalizeLineEndings(File.ReadAllText(Path.Combine(inputRoot, "second.txt")));
        File.WriteAllText(Path.Combine(repositoryPath, "renamed.txt"), secondText, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        await RunGitCommandAsync(repositoryPath, null, "add", "renamed.txt").ConfigureAwait(false);
        environment = CreateGitOracleEnvironment("1704240000 +0000");
        await RunGitCommandAsync(repositoryPath, environment, "commit", "--no-gpg-sign", "--no-verify", "-m", "replace historical oracle secret").ConfigureAwait(false);

        string commits = await RunGitCommandAsync(repositoryPath, null, "log", "--format=%H", "--reverse").ConfigureAwait(false);
        Assert.AreEqual(
            "9c2acf9cd35f6c914889821d4a0854085d66fc88\n101a379c6917407fa993bf84bdf36f522e9d8259\n887b7111ed094fa3aa9de0edb2d2553057e58edb",
            NormalizeLineEndings(commits).TrimEnd());
    }

    private static Dictionary<string, string?> CreateGitOracleEnvironment(string date)
    {
        return new Dictionary<string, string?>
        {
            ["GIT_AUTHOR_NAME"] = "Picket Oracle",
            ["GIT_AUTHOR_EMAIL"] = "picket@example.com",
            ["GIT_AUTHOR_DATE"] = date,
            ["GIT_COMMITTER_NAME"] = "Picket Oracle",
            ["GIT_COMMITTER_EMAIL"] = "picket@example.com",
            ["GIT_COMMITTER_DATE"] = date,
        };
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
