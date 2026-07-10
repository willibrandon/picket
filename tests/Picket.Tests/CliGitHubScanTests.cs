using System.Diagnostics;

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
    /// Verifies that GitHub remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedGitHubRemoteDownloads()
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
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
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
    /// Verifies that native scan can enumerate a GitHub pull request head repository.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubPullRequestHeadFiles()
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
            "--github-pull-request",
            "42",
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
        Assert.Contains("\"file\":\"github/forker/picket-fork/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("/repos/willibrandon/picket/pulls/42", server.RequestTargets);
        Assert.Contains("/repos/forker/picket-fork/git/trees/abcdef1234567890?", server.RequestTargets);
        Assert.Contains("ref=abcdef1234567890", server.RequestTargets);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitHub issue bodies and comments.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubIssueBodiesAndComments()
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
            "--github-include-issues",
            "--github-issue-state",
            "closed",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"github/willibrandon/picket/issues/7.md\"", result.Stdout);
        Assert.Contains("\"file\":\"github/willibrandon/picket/issues/7/comments/99.md\"", result.Stdout);
        Assert.Contains("/repos/willibrandon/picket/issues?", server.RequestTargets);
        Assert.Contains("state=closed", server.RequestTargets);
        Assert.Contains("/repos/willibrandon/picket/issues/7/comments?", server.RequestTargets);
        Assert.DoesNotContain("/repos/willibrandon/picket/issues/8/comments?", server.RequestTargets);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitHub release bodies and release assets.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubReleaseBodiesAndAssets()
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
            "--github-include-releases",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"github/willibrandon/picket/releases/v1.0.0.md\"", result.Stdout);
        Assert.Contains("\"file\":\"github/willibrandon/picket/releases/v1.0.0/assets/artifact.txt\"", result.Stdout);
        Assert.Contains("/repos/willibrandon/picket/releases?", server.RequestTargets);
        Assert.Contains("/repos/willibrandon/picket/releases/assets/501", server.RequestTargets);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitHub Actions artifact ZIP entries.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubActionsArtifacts()
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
            "--github-include-actions-artifacts",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"github/willibrandon/picket/actions/artifacts/build-701.zip!nested/secret.txt\"", result.Stdout);
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts?", server.RequestTargets);
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts/701/zip", server.RequestTargets);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
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
    /// Verifies that native scan can enumerate GitHub user repositories.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubUserRepositories()
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
            "--github-user",
            "octocat",
            "--github-repository-type",
            "owner",
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
        Assert.Contains("\"file\":\"github/octocat/hello/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("/api/v3/users/octocat/repos?", server.RequestTargets);
        Assert.Contains("type=owner", server.RequestTargets);
        Assert.Contains("Bearer ", server.LastAuthorization);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate authenticated GitHub gists.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitHubAuthenticatedGists()
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
            "--github-gists",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"github/gists/willibrandon/auth-gist/secret.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"github/gists/willibrandon/auth-gist/raw.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"github/gists/willibrandon/auth-gist/comments/77.md\"", result.Stdout);
        Assert.Contains("/api/v3/gists?", server.RequestTargets);
        Assert.Contains("/api/v3/gists/auth-gist", server.RequestTargets);
        Assert.Contains("/api/v3/gists/auth-gist/comments?", server.RequestTargets);
        Assert.Contains("/raw/gists/auth-gist/raw.txt", server.RequestTargets);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub pull request scans cannot also include issue enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitHubPullRequestAndIssues()
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
            "--github-pull-request",
            "42",
            "--github-include-issues",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("cannot combine --github-pull-request with --github-include-issues", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that gist source scans cannot also include issue enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitHubGistAndIssues()
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
            "--github-gist",
            "auth-gist",
            "--github-include-issues",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("GitHub issue source options require --github-repository, --github-organization, or --github-user", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub pull request scans cannot also include release enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitHubPullRequestAndReleases()
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
            "--github-pull-request",
            "42",
            "--github-include-releases",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("cannot combine --github-pull-request with --github-include-releases", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub pull request scans cannot also include Actions artifact enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitHubPullRequestAndActionsArtifacts()
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
            "--github-pull-request",
            "42",
            "--github-include-actions-artifacts",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("cannot combine --github-pull-request with --github-include-actions-artifacts", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stdout);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitHub pull request scans cannot also pin a separate ref.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitHubRefAndPullRequest()
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
            "--github-ref",
            "main",
            "--github-pull-request",
            "42",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("either --github-ref or --github-pull-request", result.Stderr);
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
        Assert.Contains("Choose one GitHub scan target: --github-repository owner/name, --github-organization login, --github-user login, --github-gist id, --github-gists, or --github-user-gists login", result.Stderr);
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
}
