using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests native GitHub source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliGitHubScanTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate GitHub repository files and scan them through the normal report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubRepositoryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitHubFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--github-source-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--github-repository",
            "willibrandon/picket",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"github/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.Contains("application/vnd.github.raw", server.LastAccept);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub source scans can use the shared GitHub API endpoint flag without enabling live validation.
    /// </summary>
    [TestMethod]
    public async Task ScanAcceptsSharedGitHubApiEndpointForSource()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitHubFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--github-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--github-repository",
            "willibrandon/picket",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"github/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.DoesNotContain("live provider options require --verify", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitHub organization repositories.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubOrganizationRepositories()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitHubFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--github-source-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--github-organization",
            "willibrandon",
            "--github-repository-type",
            "sources",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"github/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native GitHub scan endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicGitHubEndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--github-source-api-endpoint",
            "https://127.0.0.1/api/v3/",
            "--github-repository",
            "willibrandon/picket",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("blocked GitHub endpoint", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub source scans require one repository selector.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMultipleGitHubRepositorySelectors()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--github-repository",
            "willibrandon/picket",
            "--github-organization",
            "willibrandon",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("GitHub source scan requires exactly one of --github-repository or --github-organization", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    private const int UnknownFlagExitCode = 126;

    private async Task<CliResult> RunCliWithEnvironmentAsync(
        string workingDirectory,
        IReadOnlyDictionary<string, string?> environment,
        params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
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

        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG");
        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG_TOML");
        process.StartInfo.Environment.Remove("PICKET_CONFIG");
        process.StartInfo.Environment.Remove("PICKET_CONFIG_TOML");
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

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
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
