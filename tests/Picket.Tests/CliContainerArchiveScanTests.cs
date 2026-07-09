using System.Diagnostics;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests native local container archive scanning through the built executable.
/// </summary>
[TestClass]
public sealed class CliContainerArchiveScanTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Docker archive scans reach layer files through the normal native report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsDockerArchiveLayerFiles()
    {
        using TempDirectory temp = TempDirectory.Create();
        string configPath = WriteTokenConfig(temp.Path);
        string archivePath = Path.Combine(temp.Path, "image.tar");
        byte[] layerBytes = TarTestData.CreateTarBytes(("app/settings.txt", Encoding.UTF8.GetBytes("token-12345")));
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("manifest.json", Encoding.UTF8.GetBytes("""[{"Layers":["layer/layer.tar"]}]""")),
                ("layer/layer.tar", layerBytes)));

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"docker-archive/image.tar!layer/layer.tar!app/settings.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scan rejects conflicting container and source-host providers.
    /// </summary>
    [TestMethod]
    public async Task ScanRejectsMultipleNativeSourceProviders()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = Path.Combine(temp.Path, "image.tar");
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(("manifest.json", Encoding.UTF8.GetBytes("[]"))));

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "--github-repository",
            "willibrandon/picket").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("scan accepts only one native source provider at a time", result.Stderr);
    }

    private async Task<CliResult> RunCliFromDirectoryAsync(string workingDirectory, params string[] arguments)
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
