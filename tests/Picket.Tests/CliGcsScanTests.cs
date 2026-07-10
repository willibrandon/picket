using System.Diagnostics;

namespace Picket.Tests;

/// <summary>
/// Tests native Google Cloud Storage source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliGcsScanTests
{
    private const int UnknownFlagExitCode = 126;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate GCS objects with bearer-token authentication.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsGcsBucketObjects()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new GcsFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GCS_SOURCE_TEST_TOKEN"] = "gcs-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gcs-endpoint",
            server.Endpoint.AbsoluteUri,
            "--gcs-bucket",
            "secrets",
            "--gcs-prefix",
            "prod/",
            "--gcs-token-env",
            "PICKET_GCS_SOURCE_TEST_TOKEN",
            "--gcs-user-project",
            "billing-project",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"gcs/secrets/prod/appsettings.txt\"", result.Stdout);
        Assert.AreEqual("Bearer gcs-source-token", server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/storage/v1/b/secrets/o?maxResults=1000&projection=noAcl&prefix=prod%2F&userProject=billing-project", server.RequestTargets);
        Assert.Contains("/storage/v1/b/secrets/o/prod%2Fappsettings.txt?alt=media&userProject=billing-project", server.RequestTargets);
        Assert.DoesNotContain("gcs-source-token", result.Stdout);
        Assert.DoesNotContain("gcs-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that GCS source scans block non-public endpoints by default.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicGcsEndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GCS_SOURCE_TEST_TOKEN"] = "gcs-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gcs-endpoint",
            "https://127.0.0.1:1/",
            "--gcs-bucket",
            "secrets",
            "--gcs-token-env",
            "PICKET_GCS_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("blocked GCS endpoint: endpoint resolves to a non-public address", result.Stderr);
        Assert.DoesNotContain("gcs-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that GCS remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedGcsRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GCS_SOURCE_TEST_TOKEN"] = "gcs-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gcs-bucket",
            "secrets",
            "--gcs-token-env",
            "PICKET_GCS_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("gcs-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that missing GCS credentials fail before the scanner contacts a source endpoint.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMissingGcsToken()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_GCS_SOURCE_TEST_TOKEN"] = null,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--gcs-bucket",
            "secrets",
            "--gcs-token-env",
            "PICKET_GCS_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("GCS token environment variable is not set: PICKET_GCS_SOURCE_TEST_TOKEN", result.Stderr);
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
