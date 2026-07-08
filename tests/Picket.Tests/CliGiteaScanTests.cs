using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests native Gitea source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliGiteaScanTests
{
    private const int UnknownFlagExitCode = 126;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate Gitea repository files and scan them through the normal report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGiteaRepositoryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GiteaFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitea/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.AreEqual("token gitea-source-secret", server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/api/v1/repos/willibrandon/picket", server.RequestTargets);
        Assert.Contains("/api/v1/repos/willibrandon/picket/branches/main", server.RequestTargets);
        Assert.Contains("/api/v1/repos/willibrandon/picket/git/trees/abcdef1234567890?", server.RequestTargets);
        Assert.Contains("/api/v1/repos/willibrandon/picket/raw/src/appsettings.txt?ref=main", server.RequestTargets);
        Assert.DoesNotContain("gitea-source-secret", result.Stdout);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Gitea issue bodies and comments.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGiteaIssueBodiesAndComments()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GiteaFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-include-issues",
            "--gitea-issue-state",
            "closed",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"gitea/willibrandon/picket/issues/7.md\"", result.Stdout);
        Assert.Contains("\"file\":\"gitea/willibrandon/picket/issues/7/comments/99.md\"", result.Stdout);
        Assert.Contains("/api/v1/repos/willibrandon/picket/issues?state=closed&type=issues", server.RequestTargets);
        Assert.Contains("/api/v1/repos/willibrandon/picket/issues/comments?", server.RequestTargets);
        Assert.DoesNotContain("skip-token-999", result.Stdout);
        Assert.DoesNotContain("gitea-source-secret", result.Stdout);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Gitea release notes and assets.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGiteaReleaseNotesAndAssets()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GiteaFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-include-releases",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"gitea/willibrandon/picket/releases/v1.0.0.md\"", result.Stdout);
        Assert.Contains("\"file\":\"gitea/willibrandon/picket/releases/v1.0.0/assets/artifact.txt\"", result.Stdout);
        Assert.Contains("/api/v1/repos/willibrandon/picket/releases?page=1&limit=100", server.RequestTargets);
        Assert.Contains("/downloads/artifact.txt", server.RequestTargets);
        Assert.DoesNotContain("gitea-source-secret", result.Stdout);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Gitea pull request source files.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGiteaPullRequestSourceFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GiteaFixtureServer("pr-token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-pull-request",
            "7",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitea/forker/picket-fork/src/pr.txt\"", result.Stdout);
        Assert.Contains("/api/v1/repos/willibrandon/picket/pulls/7", server.RequestTargets);
        Assert.Contains("/api/v1/repos/forker/picket-fork/git/trees/pr-head-sha?", server.RequestTargets);
        Assert.Contains("/api/v1/repos/forker/picket-fork/raw/src/pr.txt?ref=pr-head-sha", server.RequestTargets);
        Assert.DoesNotContain("/api/v1/repos/willibrandon/picket/git/trees/", server.RequestTargets);
        Assert.DoesNotContain("gitea-source-secret", result.Stdout);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects ambiguous Gitea ref and pull request selectors.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGiteaRefAndPullRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-ref",
            "main",
            "--gitea-pull-request",
            "7",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Gitea source scan accepts either --gitea-ref or --gitea-pull-request, not both", result.Stderr);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Gitea pull request and issue enumeration together.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGiteaPullRequestAndIssues()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-pull-request",
            "7",
            "--gitea-include-issues",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Gitea source scan cannot combine --gitea-pull-request with --gitea-include-issues", result.Stderr);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Gitea pull request and release enumeration together.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGiteaPullRequestAndReleases()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-pull-request",
            "7",
            "--gitea-include-releases",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Gitea source scan cannot combine --gitea-pull-request with --gitea-include-releases", result.Stderr);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that Gitea remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedGiteaRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that missing Gitea credentials fail before the scanner contacts a source endpoint.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMissingGiteaToken()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = null,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Gitea token environment variable is not set: PICKET_GITEA_SOURCE_TEST_TOKEN", result.Stderr);
    }

    /// <summary>
    /// Verifies that repository URLs cannot smuggle credentials or request metadata.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGiteaRepositoryUrlMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITEA_SOURCE_TEST_TOKEN"] = "gitea-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitea-repository",
            "https://user:password@gitea.example.com/willibrandon/picket?x=1#frag",
            "--gitea-token-env",
            "PICKET_GITEA_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Gitea repository URLs must not include user info, query, or fragment data.", result.Stderr);
        Assert.DoesNotContain("gitea-source-secret", result.Stderr);
    }

    private async Task<CliResult> RunCliWithEnvironmentAsync(
        string workingDirectory,
        IReadOnlyDictionary<string, string?> environment,
        params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
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
