using System.Diagnostics;

namespace Picket.Tests;

/// <summary>
/// Tests native remote container registry scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliContainerRegistryScanTests
{
    private const int NativeOperationalExitCode = 2;
    private const string TokenEnvironmentVariable = "PICKET_REGISTRY_TEST_TOKEN";

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that registry scans acquire a pull token and scan verified image layer content.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsContainerRegistryImageLayerFiles()
    {
        using TempDirectory temp = TempDirectory.Create();
        using var server = new ContainerRegistryFixtureServer("token-24680");
        string configPath = WriteTokenConfig(temp.Path);

        CliResult result = await RunCliWithEnvironmentAsync(
            temp.Path,
            new Dictionary<string, string?>(),
            "scan",
            "--registry-image",
            "registry.example/team/image:latest",
            "--registry-endpoint",
            server.Endpoint.AbsoluteUri,
            "--registry-platform",
            "linux/x64",
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"registry/registry.example/team/image/tags/latest/resolved/sha256/", result.Stdout);
        Assert.Contains("layer.tar.gz!app/settings.txt", result.Stdout);
        Assert.Contains("\"secret\":\"token-24680\"", result.Stdout);
        Assert.Contains("/token?", server.RequestTargets);
        Assert.AreEqual($"Bearer {ContainerRegistryFixtureServer.BearerToken}", server.LastAuthorization);
    }

    /// <summary>
    /// Verifies that pre-issued registry tokens are read from the environment and never rendered.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsPreissuedRegistryTokenFromEnvironment()
    {
        using TempDirectory temp = TempDirectory.Create();
        using var server = new ContainerRegistryFixtureServer("token-13579");
        string configPath = WriteTokenConfig(temp.Path);
        var environment = new Dictionary<string, string?>
        {
            [TokenEnvironmentVariable] = ContainerRegistryFixtureServer.BearerToken,
        };

        CliResult result = await RunCliWithEnvironmentAsync(
            temp.Path,
            environment,
            "scan",
            "--registry-image",
            "registry.example/team/image:latest",
            "--registry-endpoint",
            server.Endpoint.AbsoluteUri,
            "--registry-token-env",
            TokenEnvironmentVariable,
            "--allow-non-public-source-endpoints",
            "--allow-insecure-source-endpoints",
            "-c",
            configPath,
            "-f",
            "jsonl",
            "--redact=100").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"secret\":\"REDACTED\"", result.Stdout);
        Assert.DoesNotContain(ContainerRegistryFixtureServer.BearerToken, result.Stdout);
        Assert.DoesNotContain(ContainerRegistryFixtureServer.BearerToken, result.Stderr);
        Assert.DoesNotContain("/token?", server.RequestTargets);
    }

    /// <summary>
    /// Verifies explicitly supplied registry credential options require valid environment variable names.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsInvalidCredentialEnvironmentVariableNames()
    {
        using TempDirectory temp = TempDirectory.Create();

        CliResult empty = await RunCliWithEnvironmentAsync(
            temp.Path,
            new Dictionary<string, string?>(),
            "scan",
            "--registry-image",
            "ubuntu",
            "--registry-token-env=").ConfigureAwait(false);
        CliResult invalid = await RunCliWithEnvironmentAsync(
            temp.Path,
            new Dictionary<string, string?>(),
            "scan",
            "--registry-image",
            "ubuntu",
            "--registry-token-env",
            "PICKET=REGISTRY").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, empty.ExitCode);
        Assert.Contains("environment variable names must not be empty", empty.Stderr);
        Assert.AreEqual(NativeOperationalExitCode, invalid.ExitCode);
        Assert.Contains("environment variable name is invalid", invalid.Stderr);
    }

    /// <summary>
    /// Verifies registry scans reject mixed or incomplete credential modes before making a request.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsAmbiguousCredentialModes()
    {
        using TempDirectory temp = TempDirectory.Create();
        var environment = new Dictionary<string, string?>
        {
            [TokenEnvironmentVariable] = "registry-token",
            ["PICKET_REGISTRY_TEST_PASSWORD"] = "registry-password",
            ["PICKET_REGISTRY_TEST_USERNAME"] = "picket-user",
        };

        CliResult mixed = await RunCliWithEnvironmentAsync(
            temp.Path,
            environment,
            "scan",
            "--registry-image",
            "ubuntu",
            "--registry-token-env",
            TokenEnvironmentVariable,
            "--registry-username-env",
            "PICKET_REGISTRY_TEST_USERNAME",
            "--registry-password-env",
            "PICKET_REGISTRY_TEST_PASSWORD").ConfigureAwait(false);
        CliResult incomplete = await RunCliWithEnvironmentAsync(
            temp.Path,
            environment,
            "scan",
            "--registry-image",
            "ubuntu",
            "--registry-username-env",
            "PICKET_REGISTRY_TEST_USERNAME").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, mixed.ExitCode);
        Assert.Contains("either --registry-token-env or both --registry-username-env and --registry-password-env", mixed.Stderr);
        Assert.AreEqual(NativeOperationalExitCode, incomplete.ExitCode);
        Assert.Contains("either --registry-token-env or both --registry-username-env and --registry-password-env", incomplete.Stderr);
    }

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
#if DEBUG
        return "Debug";
#else
        return "Release";
#endif
    }

    private static string GetRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory, "Picket.slnx")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new DirectoryNotFoundException("Could not find repository root.");
    }
}
