using System.Diagnostics;
namespace Picket.Tests;

/// <summary>
/// Tests native remote source endpoint guard behavior through the built executable.
/// </summary>
[TestClass]
public sealed class CliSourceEndpointGuardTests
{
    private const int UnknownFlagExitCode = 126;
    private const string TokenEnvironmentVariable = "PICKET_SOURCE_ENDPOINT_GUARD_TOKEN";
    private const string TokenValue = "source-endpoint-guard-secret";

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native Gitea source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicGiteaEndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked Gitea endpoint",
            CreateTokenEnvironment(),
            "--gitea-api-endpoint",
            "https://127.0.0.1/api/v1/",
            "--gitea-repository",
            "willibrandon/picket",
            "--gitea-token-env",
            TokenEnvironmentVariable).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that native Bitbucket source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicBitbucketEndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked Bitbucket endpoint",
            CreateTokenEnvironment(),
            "--bitbucket-api-endpoint",
            "https://127.0.0.1/2.0/",
            "--bitbucket-repository",
            "willibrandon/picket",
            "--bitbucket-token-env",
            TokenEnvironmentVariable).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that native GitLab source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicGitLabEndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked GitLab endpoint",
            CreateTokenEnvironment(),
            "--gitlab-api-endpoint",
            "https://127.0.0.1/api/v4/",
            "--gitlab-project",
            "willibrandon/picket",
            "--gitlab-token-env",
            TokenEnvironmentVariable).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that native Amazon S3 source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicS3EndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked S3 endpoint",
            new Dictionary<string, string?>
            {
                ["PICKET_SOURCE_ENDPOINT_GUARD_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE",
                ["PICKET_SOURCE_ENDPOINT_GUARD_SECRET_ACCESS_KEY"] = TokenValue,
            },
            "--s3-endpoint",
            "https://127.0.0.1/",
            "--s3-bucket",
            "secrets",
            "--s3-region",
            "us-east-1",
            "--s3-access-key-id-env",
            "PICKET_SOURCE_ENDPOINT_GUARD_ACCESS_KEY_ID",
            "--s3-secret-access-key-env",
            "PICKET_SOURCE_ENDPOINT_GUARD_SECRET_ACCESS_KEY").ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that native Google Cloud Storage source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicGcsEndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked GCS endpoint",
            CreateTokenEnvironment(),
            "--gcs-endpoint",
            "https://127.0.0.1/storage/v1/",
            "--gcs-bucket",
            "secrets",
            "--gcs-token-env",
            TokenEnvironmentVariable).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that native Azure Blob Storage source endpoints are guarded before any provider request is made.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicAzureBlobEndpointByDefault()
    {
        await AssertBlocksNonPublicEndpointAsync(
            "blocked Azure Blob endpoint",
            CreateTokenEnvironment(),
            "--azure-blob-endpoint",
            "https://127.0.0.1/",
            "--azure-blob-container",
            "logs",
            "--azure-blob-token-env",
            TokenEnvironmentVariable).ConfigureAwait(false);
    }

    private async Task AssertBlocksNonPublicEndpointAsync(
        string expectedMessage,
        IReadOnlyDictionary<string, string?> environment,
        params string[] sourceArguments)
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var arguments = new List<string>(sourceArguments.Length + 5)
        {
            "scan",
        };
        arguments.AddRange(sourceArguments);
        arguments.Add("-c");
        arguments.Add(configPath);
        arguments.Add("-f");
        arguments.Add("jsonl");

        CliResult result = await RunCliWithEnvironmentAsync(root.Path, environment, [.. arguments]).ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.Contains(expectedMessage, result.Stderr);
        foreach (string? secret in environment.Values)
        {
            if (!string.IsNullOrEmpty(secret))
            {
                Assert.DoesNotContain(secret, result.Stdout);
                Assert.DoesNotContain(secret, result.Stderr);
            }
        }
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

    private static Dictionary<string, string?> CreateTokenEnvironment()
    {
        return new Dictionary<string, string?>
        {
            [TokenEnvironmentVariable] = TokenValue,
        };
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
