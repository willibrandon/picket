using System.Diagnostics;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests native Bitbucket source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliBitbucketScanTests
{
    private const int UnknownFlagExitCode = 126;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate Bitbucket repository files and scan them through the normal report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketRepositoryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.AreEqual("Bearer bitbucket-source-secret", server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/2.0/repositories/willibrandon/picket", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/src/main/?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/src/main/src/?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/src/main/src/appsettings.txt", server.RequestTargets);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that Bitbucket source scans block non-public endpoints by default.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicBitbucketEndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            "https://127.0.0.1:1/",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("blocked Bitbucket endpoint: endpoint resolves to a non-public address", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Bitbucket pull request source files.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketPullRequestSourceFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("pr-token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-pull-request",
            "7",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/forkspace/picket-fork/src/pr.txt\"", result.Stdout);
        Assert.Contains("/2.0/repositories/willibrandon/picket/pullrequests/7", server.RequestTargets);
        Assert.Contains("/2.0/repositories/forkspace/picket-fork/src/pr-head-sha/?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/forkspace/picket-fork/src/pr-head-sha/src/?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/forkspace/picket-fork/src/pr-head-sha/src/pr.txt", server.RequestTargets);
        Assert.DoesNotContain("/2.0/repositories/willibrandon/picket/src/", server.RequestTargets);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Bitbucket repository download artifacts.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketDownloadArtifacts()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("download-token-2468");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-include-downloads",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/downloads/build.txt\"", result.Stdout);
        Assert.Contains("/2.0/repositories/willibrandon/picket/downloads?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/downloads/build.txt", server.RequestTargets);
        Assert.Contains("/download-content/build.txt", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/downloads/build.txt|Bearer bitbucket-source-secret", server.RequestsWithAuthorization);
        Assert.Contains("/download-content/build.txt|", server.RequestsWithAuthorization);
        Assert.DoesNotContain("/download-content/build.txt|Bearer", server.RequestsWithAuthorization);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Bitbucket pipeline step logs.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketPipelineStepLogs()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("pipeline-token-13579");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-pipeline-id",
            "pipeline-123",
            "--bitbucket-include-pipeline-logs",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/pipelines/pipeline-123/steps/step-1.log\"", result.Stdout);
        Assert.Contains("/2.0/repositories/willibrandon/picket/pipelines/pipeline-123/steps?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/pipelines/pipeline-123/steps/step-1/log", server.RequestTargets);
        Assert.Contains("/pipeline-content/step-1.log", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/pipelines/pipeline-123/steps/step-1/log|Bearer bitbucket-source-secret", server.RequestsWithAuthorization);
        Assert.Contains("/pipeline-content/step-1.log|", server.RequestsWithAuthorization);
        Assert.DoesNotContain("/pipeline-content/step-1.log|Bearer", server.RequestsWithAuthorization);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate repositories in a Bitbucket workspace.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketWorkspaceRepositories()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("workspace-token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        int findingCount = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(line => line.Contains("\"ruleId\":\"token\"", StringComparison.Ordinal));
        Assert.AreEqual(2, findingCount);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/second/src/second.txt\"", result.Stdout);
        Assert.Contains("/2.0/repositories/willibrandon?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/src/main/src/appsettings.txt", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/second/src/main/src/second.txt", server.RequestTargets);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate repositories in a Bitbucket workspace project.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketProjectRepositories()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("project-token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-project",
            "CORE",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        int findingCount = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(line => line.Contains("\"ruleId\":\"token\"", StringComparison.Ordinal));
        Assert.AreEqual(1, findingCount);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.DoesNotContain("\"file\":\"bitbucket/willibrandon/second/src/second.txt\"", result.Stdout);
        Assert.Contains("/2.0/workspaces/willibrandon/projects/CORE", server.RequestTargets);
        Assert.Contains("q=project.key%3D%22CORE%22", server.RequestTargets);
        Assert.Contains("/2.0/repositories/willibrandon/picket/src/main/src/appsettings.txt", server.RequestTargets);
        Assert.DoesNotContain("/2.0/repositories/willibrandon/second", server.RequestTargets);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Bitbucket workspace snippets.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketWorkspaceSnippets()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("snippet-token-2468");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-include-snippets",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        int findingCount = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(line => line.Contains("\"ruleId\":\"token\"", StringComparison.Ordinal));
        Assert.AreEqual(3, findingCount);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/second/src/second.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"bitbucket/willibrandon/snippets/snippet-1/secret.txt\"", result.Stdout);
        Assert.Contains("/2.0/snippets/willibrandon?pagelen=100&page=1", server.RequestTargets);
        Assert.Contains("/2.0/snippets/willibrandon/snippet-1", server.RequestTargets);
        Assert.Contains("/2.0/snippets/willibrandon/snippet-1/files/secret.txt", server.RequestTargets);
        Assert.Contains("/2.0/snippets/willibrandon/snippet-1/rev1/files/secret.txt", server.RequestTargets);
        Assert.Contains("/2.0/snippets/willibrandon/snippet-1/rev1/files/secret.txt|Bearer bitbucket-source-secret", server.RequestsWithAuthorization);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stdout);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects ambiguous Bitbucket ref and pull request selectors.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRefAndPullRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-ref",
            "main",
            "--bitbucket-pull-request",
            "7",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket source scan accepts either --bitbucket-ref or --bitbucket-pull-request, not both", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects ambiguous Bitbucket pull request and download artifact selectors.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketPullRequestAndDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-pull-request",
            "7",
            "--bitbucket-include-downloads",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket source options cannot combine pull request scans with download artifact enumeration.", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Bitbucket pipeline IDs without log enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketPipelineWithoutLogs()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-pipeline-id",
            "pipeline-123",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--bitbucket-pipeline-id requires --bitbucket-include-pipeline-logs", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Bitbucket pipeline log scans without a pipeline ID.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketPipelineLogsWithoutPipeline()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-include-pipeline-logs",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--bitbucket-include-pipeline-logs requires --bitbucket-pipeline-id", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects ambiguous Bitbucket repository and workspace selectors.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRepositoryAndWorkspace()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket source scan requires exactly one of --bitbucket-repository or --bitbucket-workspace", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Bitbucket project scans without a workspace selector.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRepositoryAndProject()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-project",
            "CORE",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket project source scan requires --bitbucket-workspace", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Bitbucket snippet scans without a workspace selector.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRepositoryAndSnippets()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-include-snippets",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket snippet source scan requires --bitbucket-workspace", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects project-scoped Bitbucket repository scans combined with workspace snippet enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketProjectAndSnippets()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-project",
            "CORE",
            "--bitbucket-include-snippets",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket project source scan cannot be combined with workspace snippet enumeration", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan rejects Bitbucket workspace scans combined with pull request selectors.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketWorkspaceAndPullRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-workspace",
            "willibrandon",
            "--bitbucket-pull-request",
            "7",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket pull request source scan requires --bitbucket-repository", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can authenticate to Bitbucket with app-password basic authentication.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsBitbucketRepositoryFilesWithAppPassword()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new BitbucketFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-app-password",
            ["PICKET_BITBUCKET_SOURCE_TEST_USERNAME"] = "bitbucket-user",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-api-endpoint",
            server.Endpoint.AbsoluteUri,
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--bitbucket-username-env",
            "PICKET_BITBUCKET_SOURCE_TEST_USERNAME",
            "--bitbucket-token-kind",
            "app-password",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("bitbucket-user:bitbucket-app-password"));
        Assert.AreEqual(1, result.ExitCode);
        Assert.AreEqual(string.Concat("Basic ", encoded), server.LastAuthorization);
        Assert.DoesNotContain("bitbucket-app-password", result.Stdout);
        Assert.DoesNotContain("bitbucket-app-password", result.Stderr);
    }

    /// <summary>
    /// Verifies that Bitbucket remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedBitbucketRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that missing Bitbucket credentials fail before the scanner contacts a source endpoint.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMissingBitbucketToken()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = null,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket token environment variable is not set: PICKET_BITBUCKET_SOURCE_TEST_TOKEN", result.Stderr);
    }

    /// <summary>
    /// Verifies that repository URLs cannot smuggle credentials or request metadata.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRepositoryUrlMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "https://user:password@bitbucket.org/willibrandon/picket?x=1#frag",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket repository URLs must not include user info, query, or fragment data.", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that non-URL repository selectors must be exactly workspace/repository.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsBitbucketRepositoryPathWithExtraSegments()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_BITBUCKET_SOURCE_TEST_TOKEN"] = "bitbucket-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--bitbucket-repository",
            "willibrandon/picket/src/main",
            "--bitbucket-token-env",
            "PICKET_BITBUCKET_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Bitbucket repository must be a workspace/repository path or repository URL.", result.Stderr);
        Assert.DoesNotContain("bitbucket-source-secret", result.Stderr);
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
