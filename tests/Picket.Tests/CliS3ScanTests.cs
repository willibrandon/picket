using System.Diagnostics;
namespace Picket.Tests;

/// <summary>
/// Tests native S3 source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliS3ScanTests
{
    private const int NativeOperationalExitCode = 2;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate S3 objects with SigV4 authentication.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsS3BucketObjects()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new S3FixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE",
            ["PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY"] = "s3-secret-access-key",
            ["PICKET_S3_SOURCE_TEST_SESSION_TOKEN"] = "s3-session-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--s3-endpoint",
            server.Endpoint.AbsoluteUri,
            "--s3-bucket",
            "secrets",
            "--s3-region",
            "us-east-1",
            "--s3-prefix",
            "prod/",
            "--s3-access-key-id-env",
            "PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID",
            "--s3-secret-access-key-env",
            "PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY",
            "--s3-session-token-env",
            "PICKET_S3_SOURCE_TEST_SESSION_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"s3/secrets/prod/appsettings.txt\"", result.Stdout);
        Assert.Contains("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/", server.LastAuthorization);
        Assert.Contains("/us-east-1/s3/aws4_request", server.LastAuthorization);
        Assert.Contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token", server.LastAuthorization);
        Assert.AreEqual("s3-session-token", server.LastSessionToken);
        Assert.IsNotEmpty(server.LastContentHash);
        Assert.IsNotEmpty(server.LastRequestDate);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/secrets?list-type=2&max-keys=1000&prefix=prod%2F", server.RequestTargets);
        Assert.Contains("/secrets/prod/appsettings.txt", server.RequestTargets);
        Assert.Contains("--allow-insecure-source-endpoints permits source credentials over HTTP", result.Stderr);
        Assert.DoesNotContain("s3-secret-access-key", result.Stdout);
        Assert.DoesNotContain("s3-secret-access-key", result.Stderr);
        Assert.DoesNotContain("s3-session-token", result.Stdout);
        Assert.DoesNotContain("s3-session-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that S3 source scans block non-public endpoints by default.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicS3EndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE",
            ["PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY"] = "s3-secret-access-key",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--s3-endpoint",
            "https://127.0.0.1:1/",
            "--s3-bucket",
            "secrets",
            "--s3-region",
            "us-east-1",
            "--s3-access-key-id-env",
            "PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID",
            "--s3-secret-access-key-env",
            "PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("blocked S3 endpoint: endpoint resolves to a non-public address", result.Stderr);
        Assert.DoesNotContain("s3-secret-access-key", result.Stderr);
    }

    /// <summary>
    /// Verifies that S3 remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedS3RemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE",
            ["PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY"] = "s3-secret-access-key",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--s3-bucket",
            "secrets",
            "--s3-region",
            "us-east-1",
            "--s3-access-key-id-env",
            "PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID",
            "--s3-secret-access-key-env",
            "PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("s3-secret-access-key", result.Stderr);
    }

    /// <summary>
    /// Verifies that missing S3 credentials fail before the scanner contacts a source endpoint.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMissingS3SecretAccessKey()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE",
            ["PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY"] = null,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--s3-bucket",
            "secrets",
            "--s3-region",
            "us-east-1",
            "--s3-access-key-id-env",
            "PICKET_S3_SOURCE_TEST_ACCESS_KEY_ID",
            "--s3-secret-access-key-env",
            "PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("S3 secret access key environment variable is not set: PICKET_S3_SOURCE_TEST_SECRET_ACCESS_KEY", result.Stderr);
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
