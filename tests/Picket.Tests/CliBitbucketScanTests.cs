using System.Diagnostics;
using System.Runtime.InteropServices;
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
