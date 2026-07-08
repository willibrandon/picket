using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests native Azure Blob Storage source scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliAzureBlobScanTests
{
    private const int UnknownFlagExitCode = 126;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that native scan can enumerate Azure Blob Storage objects with bearer-token authentication.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureBlobContainerBlobsWithBearerToken()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureBlobFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_BLOB_SOURCE_TEST_TOKEN"] = "azure-blob-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-blob-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-blob-container",
            "secrets",
            "--azure-blob-prefix",
            "prod/",
            "--azure-blob-token-env",
            "PICKET_AZURE_BLOB_SOURCE_TEST_TOKEN",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"azure-blob/127.0.0.1/secrets/prod/appsettings.txt\"", result.Stdout);
        Assert.Contains("Bearer azure-blob-source-secret", server.LastAuthorization);
        Assert.Contains("application/octet-stream", server.LastAccept);
        Assert.Contains("/secrets?restype=container&comp=list&maxresults=5000&prefix=prod%2F", server.RequestTargets);
        Assert.Contains("/secrets/prod/appsettings.txt", server.RequestTargets);
        Assert.DoesNotContain("azure-blob-source-secret", result.Stdout);
        Assert.DoesNotContain("azure-blob-source-secret", result.Stderr);
        Assert.IsNotEmpty(server.LastStorageVersion);
    }

    /// <summary>
    /// Verifies that native scan can enumerate Azure Blob Storage objects with a shared access signature.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsAzureBlobContainerBlobsWithSharedAccessSignature()
    {
        using TempDirectory root = TempDirectory.Create();
        using var server = new AzureBlobFixtureServer("token-12345");
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_BLOB_SOURCE_TEST_SAS"] = "?sv=2026-04-06&sig=secret-signature",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-blob-endpoint",
            server.Endpoint.AbsoluteUri,
            "--azure-blob-container",
            "secrets",
            "--azure-blob-token-env",
            "PICKET_AZURE_BLOB_SOURCE_TEST_SAS",
            "--azure-blob-token-kind",
            "sas",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.IsEmpty(server.LastAuthorization);
        Assert.Contains("sv=2026-04-06", server.RequestTargets);
        Assert.Contains("sig=secret-signature", server.RequestTargets);
        Assert.DoesNotContain("secret-signature", result.Stdout);
        Assert.DoesNotContain("secret-signature", result.Stderr);
    }

    /// <summary>
    /// Verifies that Azure Blob remote source scans reject unbounded download caps.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsUnboundedAzureBlobRemoteDownloads()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_AZURE_BLOB_SOURCE_TEST_TOKEN"] = "azure-blob-source-secret",
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            root.Path,
            environment,
            "scan",
            "--azure-blob-endpoint",
            "https://picket.blob.core.windows.net/",
            "--azure-blob-container",
            "secrets",
            "--azure-blob-token-env",
            "PICKET_AZURE_BLOB_SOURCE_TEST_TOKEN",
            "--max-target-megabytes=0",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(UnknownFlagExitCode, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Remote download byte caps must be greater than zero.", result.Stderr);
        Assert.DoesNotContain("azure-blob-source-secret", result.Stderr);
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
