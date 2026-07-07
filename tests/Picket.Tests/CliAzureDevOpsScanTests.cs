using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests native Azure DevOps source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliAzureDevOpsScanTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate Azure Repos files and scan them through the normal report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureDevOpsRepositoryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureDevOpsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-repository",
            "picket",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-devops/test/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("Basic ", server.LastAuthorization);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that Azure DevOps remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedAzureDevOpsRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureDevOpsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-repository",
            "picket",
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
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can enumerate an Azure DevOps pull request source commit.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureDevOpsPullRequestSourceFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureDevOpsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-repository",
            "picket",
            "--azure-devops-pull-request",
            "42",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-devops/test/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("/pullRequests/42?", server.RequestTargets);
        Assert.Contains("versionDescriptor.version=abcdef1234567890", server.RequestTargets);
        Assert.Contains("versionDescriptor.versionType=commit", server.RequestTargets);
        Assert.Contains("Basic ", server.LastAuthorization);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can include Azure DevOps wiki backing repositories.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureDevOpsWikiFilesWhenEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureDevOpsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-include-wikis",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"azure-devops/test/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-devops-wiki/test/Team%20Wiki/Home.md\"", result.Stdout);
        Assert.Contains("Basic ", server.LastAuthorization);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scan can include Azure DevOps build artifacts and logs.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureDevOpsBuildArtifactsAndLogsWhenEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureDevOpsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-build-id",
            "77",
            "--azure-devops-include-artifacts",
            "--azure-devops-include-logs",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"azure-devops/test/picket/src/appsettings.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-devops-build/test/77/artifacts/drop.zip!nested/artifact.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-devops-build/test/77/logs/4.log\"", result.Stdout);
        Assert.Contains("/_apis/build/builds/77/artifacts?", server.RequestTargets);
        Assert.Contains("/_apis/build/builds/77/logs?", server.RequestTargets);
        Assert.Contains("Basic ", server.LastAuthorization);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that branch and pull request source scopes are mutually exclusive.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsAzureDevOpsBranchAndPullRequest()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            "https://dev.azure.com/willibrandon/",
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-branch",
            "main",
            "--azure-devops-pull-request",
            "42",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("either --azure-devops-branch or --azure-devops-pull-request", result.Stderr);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that an explicitly disabled wiki option does not trigger Azure DevOps enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanDoesNotRequireAzureDevOpsEndpointWhenWikiEnumerationIsDisabled()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            new Dictionary<string, string?>(),
            "scan",
            "--azure-devops-include-wikis=false",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.DoesNotContain("Azure DevOps source scan requires", result.Stderr);
    }

    /// <summary>
    /// Verifies that an explicitly disabled artifact option does not trigger Azure DevOps enumeration.
    /// </summary>
    [TestMethod]
    public async Task ScanDoesNotRequireAzureDevOpsEndpointWhenArtifactEnumerationIsDisabled()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            new Dictionary<string, string?>(),
            "scan",
            "--azure-devops-include-artifacts=false",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.DoesNotContain("Azure DevOps source scan requires", result.Stderr);
    }

    /// <summary>
    /// Verifies that build artifact scans require an explicit build ID.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsAzureDevOpsArtifactsWithoutBuildId()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            "https://dev.azure.com/willibrandon/",
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "--azure-devops-project",
            "test",
            "--azure-devops-include-artifacts",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("--azure-devops-build-id", result.Stderr);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
    }

    /// <summary>
    /// Verifies that native Azure DevOps scan endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicAzureDevOpsEndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_DEVOPS_TEST_TOKEN"] = "test-pat-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-devops-endpoint",
            "https://127.0.0.1/willibrandon/",
            "--azure-devops-token-env",
            "PICKET_AZURE_DEVOPS_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains("blocked Azure DevOps endpoint", result.Stderr);
        Assert.DoesNotContain("test-pat-secret", result.Stdout);
        Assert.DoesNotContain("test-pat-secret", result.Stderr);
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
