using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests native GitLab source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliGitLabScanTests
{
    private const int UnknownFlagExitCode = 126;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate GitLab repository files and scan them through the normal report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabRepositoryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/repository/tree?", server.RequestTargets);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate a GitLab merge request source head.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabMergeRequestHeadFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-merge-request",
            "42",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab/123/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/merge_requests/42", server.RequestTargets);
        Assert.Contains("/api/v4/projects/123/repository/tree?", server.RequestTargets);
        Assert.Contains("ref=abcdef1234567890", server.RequestTargets);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitLab project snippets.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabProjectSnippets()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-include-snippets",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab-snippet/willibrandon/picket/7/ops/token.txt\"", result.Stdout);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/snippets?", server.RequestTargets);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/snippets/7/raw", server.RequestTargets);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitLab job trace logs and artifact archives.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabJobLogsAndArtifacts()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-include-job-logs",
            "--gitlab-include-job-artifacts",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab-job-log/willibrandon/picket/99-build.log\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab-job-artifact/willibrandon/picket/99/artifacts.zip!out/secret.txt\"", result.Stdout);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs?", server.RequestTargets);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/trace", server.RequestTargets);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/artifacts", server.RequestTargets);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate GitLab job trace logs and artifact archives from a selected pipeline.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabPipelineJobLogsAndArtifacts()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-pipeline-id",
            "123",
            "--gitlab-include-job-logs",
            "--gitlab-include-job-artifacts",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab-job-log/willibrandon/picket/99-build.log\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab-job-artifact/willibrandon/picket/99/artifacts.zip!out/secret.txt\"", result.Stdout);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/pipelines/123/jobs?", server.RequestTargets);
        Assert.DoesNotContain("/api/v4/projects/willibrandon%2Fpicket/jobs?per_page", server.RequestTargets);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/trace", server.RequestTargets);
        Assert.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/artifacts", server.RequestTargets);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate projects in a GitLab group.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGitLabGroupProjects()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GitLabFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gitlab-group",
            "team/platform",
            "--gitlab-include-subgroups",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gitlab/team/platform/api/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("/api/v4/groups/team%2Fplatform/projects?", server.RequestTargets);
        Assert.Contains("include_subgroups=true", server.RequestTargets);
        Assert.Contains("/api/v4/projects/team%2Fplatform%2Fapi/repository/tree?", server.RequestTargets);
        Assert.AreEqual("gitlab-source-secret", server.LastPrivateToken);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.DoesNotContain("gitlab-source-secret", result.Stdout);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that GitLab remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedGitLabRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that branch and merge request source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabRefAndMergeRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-ref",
            "main",
            "--gitlab-merge-request",
            "42",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GitLab source options accept either a ref or a merge request ID, not both.", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that project and group source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabProjectAndGroup()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-group",
            "team/platform",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GitLab source scan accepts either --gitlab-project or --gitlab-group, not both", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that merge request scans require a project source.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabGroupAndMergeRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-group",
            "team/platform",
            "--gitlab-merge-request",
            "42",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--gitlab-merge-request requires --gitlab-project", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that pipeline-scoped job enumeration requires a project source.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabGroupAndPipeline()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-group",
            "team/platform",
            "--gitlab-pipeline-id",
            "123",
            "--gitlab-include-job-logs",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--gitlab-pipeline-id requires --gitlab-project", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that pipeline-scoped job enumeration requires a selected job source.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabPipelineWithoutJobEnumeration()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-pipeline-id",
            "123",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--gitlab-pipeline-id requires --gitlab-include-job-logs or --gitlab-include-job-artifacts", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that merge request and snippet source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabMergeRequestAndSnippets()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-merge-request",
            "42",
            "--gitlab-include-snippets",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GitLab source options cannot combine merge request scans with snippet enumeration.", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that merge request and job artifact source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabMergeRequestAndJobArtifacts()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-merge-request",
            "42",
            "--gitlab-include-job-artifacts",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GitLab source options cannot combine merge request scans with job artifact enumeration.", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that merge request and job log source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsGitLabMergeRequestAndJobLogs()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-merge-request",
            "42",
            "--gitlab-include-job-logs",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GitLab source options cannot combine merge request scans with job log enumeration.", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that source provider selection rejects GitHub and GitLab source options together.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMixedGitHubAndGitLabSourceOptions()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GITLAB_SOURCE_TEST_TOKEN"] = "gitlab-source-secret",
            ["PICKET_GITHUB_SOURCE_TEST_TOKEN"] = "github-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-token-env",
            "PICKET_GITLAB_SOURCE_TEST_TOKEN",
            "--github-repository",
            "willibrandon/picket",
            "--github-token-env",
            "PICKET_GITHUB_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("scan accepts only one native source provider at a time", result.Stderr);
        Assert.DoesNotContain("gitlab-source-secret", result.Stderr);
        Assert.DoesNotContain("github-source-secret", result.Stderr);
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
