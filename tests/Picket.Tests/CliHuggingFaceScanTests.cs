using System.Diagnostics;

namespace Picket.Tests;

/// <summary>
/// Tests native Hugging Face source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliHuggingFaceScanTests
{
    private const int NativeOperationalExitCode = 2;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan enumerates a Hugging Face model with bearer-token authentication.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsHuggingFaceModel()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new HuggingFaceFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN"] = "hf-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--huggingface-endpoint",
            server.Endpoint.AbsoluteUri,
            "--huggingface-model",
            "owner/project",
            "--huggingface-token-env",
            "PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains(
            "\"file\":\"huggingface/model/owner/project/abc123/secret.txt\"",
            result.Stdout);
        Assert.Contains("\"type\":\"huggingface-model\"", result.Stdout);
        Assert.AreEqual("Bearer hf-source-token", server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains(
            "/api/models/owner/project/revision/main",
            server.RequestTargets);
        Assert.Contains(
            "/api/models/owner/project/tree/abc123?recursive=true&expand=true",
            server.RequestTargets);
        Assert.Contains(
            "/owner/project/resolve/abc123/secret.txt",
            server.RequestTargets);
        Assert.DoesNotContain("hf-source-token", result.Stdout);
        Assert.DoesNotContain("hf-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that Hugging Face scans require exactly one resource selector.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsAmbiguousHuggingFaceSelectors()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN"] = "hf-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--huggingface-model",
            "owner/model",
            "--huggingface-dataset",
            "owner/data",
            "--huggingface-token-env",
            "PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains(
            "requires exactly one of --huggingface-model, --huggingface-dataset, --huggingface-space, or --huggingface-bucket",
            result.Stderr);
        Assert.DoesNotContain("hf-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that missing Hugging Face credentials fail before endpoint access.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMissingHuggingFaceToken()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN"] = null,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--huggingface-model",
            "owner/project",
            "--huggingface-token-env",
            "PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains(
            "Hugging Face token environment variable is not set: PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            result.Stderr);
    }

    /// <summary>
    /// Verifies that Hugging Face source scans block non-public endpoints by default.
    /// </summary>
    [TestMethod]
    public async Task ScanBlocksNonPublicHuggingFaceEndpointByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN"] = "hf-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--huggingface-endpoint",
            "https://127.0.0.1:1/",
            "--huggingface-model",
            "owner/project",
            "--huggingface-token-env",
            "PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains(
            "blocked Hugging Face endpoint: endpoint resolves to a non-public address",
            result.Stderr);
        Assert.DoesNotContain("hf-source-token", result.Stderr);
    }

    /// <summary>
    /// Verifies that Hugging Face remote source scans reject an unbounded download cap.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedHuggingFaceDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN"] = "hf-source-token",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--huggingface-model",
            "owner/project",
            "--huggingface-token-env",
            "PICKET_HUGGINGFACE_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("hf-source-token", result.Stderr);
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
        string stdout = await process.StandardOutput.ReadToEndAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(
            TestContext.CancellationToken).ConfigureAwait(false);
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
