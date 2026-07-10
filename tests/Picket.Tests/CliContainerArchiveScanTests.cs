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
    /// Verifies that OCI archive scans reach gzip layer blobs through the normal native report path.
    /// </summary>
    [TestMethod]
    public async Task ScanReadsOciArchiveLayerFiles()
    {
        using TempDirectory temp = TempDirectory.Create();
        string configPath = WriteTokenConfig(temp.Path);
        string archivePath = Path.Combine(temp.Path, "image-oci.tar");
        byte[] layerBytes = TarTestData.CreateTarBytes(("etc/secret.conf", Encoding.UTF8.GetBytes("token-67890")));
        byte[] layerGzipBytes = TarTestData.CreateGzipBytes(layerBytes);
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("oci-layout", Encoding.UTF8.GetBytes("""{"imageLayoutVersion":"1.0.0"}""")),
                ("index.json", Encoding.UTF8.GetBytes("""{"manifests":[]}""")),
                ("blobs/sha256/layer", layerGzipBytes)));

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--oci-archive",
            archivePath,
            "-c",
            configPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"oci-archive/image-oci.tar!blobs/sha256/layer!etc/secret.conf\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-67890\"", result.Stdout);
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

    /// <summary>
    /// Verifies a failed report retains scan progress and a retry restores the complete result.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointResumesAfterReportFailure()
    {
        using TempDirectory temp = TempDirectory.Create();
        string configPath = WriteTokenConfig(temp.Path);
        string archivePath = WriteDockerArchive(temp.Path, "token-12345");
        string checkpointPath = Path.Combine(temp.Path, "scan.checkpoint");
        CliResult failed = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "-f",
            "jsonl",
            "-r",
            temp.Path).ConfigureAwait(false);

        Assert.AreEqual(1, failed.ExitCode);
        Assert.Contains("failed to write report", failed.Stderr);
        Assert.IsTrue(File.Exists(checkpointPath));

        string reportPath = Path.Combine(temp.Path, "result.jsonl");
        CliResult resumed = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "-f",
            "jsonl",
            "-r",
            reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, resumed.ExitCode);
        Assert.Contains("resuming checkpoint:", resumed.Stderr);
        Assert.Contains("\"secret\":\"token-12345\"", File.ReadAllText(reportPath));
        Assert.IsFalse(File.Exists(checkpointPath));
    }

    /// <summary>
    /// Verifies source mutations invalidate retained checkpoint state.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointRejectsChangedSourceManifest()
    {
        using TempDirectory temp = TempDirectory.Create();
        string configPath = WriteTokenConfig(temp.Path);
        string archivePath = WriteDockerArchive(temp.Path, "token-12345");
        string checkpointPath = Path.Combine(temp.Path, "scan.checkpoint");
        CliResult failed = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "-f",
            "jsonl",
            "-r",
            temp.Path).ConfigureAwait(false);
        Assert.AreEqual(1, failed.ExitCode);
        WriteDockerArchive(temp.Path, "token-67890");

        CliResult changed = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, changed.ExitCode);
        Assert.Contains("checkpoint does not match the current scan or source snapshot", changed.Stderr.ToLowerInvariant());
        Assert.IsTrue(File.Exists(checkpointPath));
    }

    /// <summary>
    /// Verifies explicit reset starts a changed source snapshot from the beginning.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointResetAcceptsChangedSourceManifest()
    {
        using TempDirectory temp = TempDirectory.Create();
        string configPath = WriteTokenConfig(temp.Path);
        string archivePath = WriteDockerArchive(temp.Path, "token-12345");
        string checkpointPath = Path.Combine(temp.Path, "scan.checkpoint");
        CliResult failed = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "-f",
            "jsonl",
            "-r",
            temp.Path).ConfigureAwait(false);
        Assert.AreEqual(1, failed.ExitCode);
        WriteDockerArchive(temp.Path, "token-67890");

        CliResult reset = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "-c",
            configPath,
            "--checkpoint",
            checkpointPath,
            "--checkpoint-reset",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, reset.ExitCode);
        Assert.Contains("\"secret\":\"token-67890\"", reset.Stdout);
        Assert.DoesNotContain("resuming checkpoint:", reset.Stderr);
        Assert.IsFalse(File.Exists(checkpointPath));
    }

    /// <summary>
    /// Verifies checkpoint state cannot overwrite a requested report.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointRejectsReportPathCollision()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = WriteDockerArchive(temp.Path, "token-12345");
        string checkpointPath = Path.Combine(temp.Path, "scan.checkpoint");

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "--checkpoint",
            checkpointPath,
            "-r",
            checkpointPath).ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("checkpoint path must be different from every report path", result.Stderr);
    }

    /// <summary>
    /// Verifies checkpointing is limited to native source-provider scans.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointRequiresSourceProvider()
    {
        using TempDirectory temp = TempDirectory.Create();
        string checkpointPath = Path.Combine(temp.Path, "scan.checkpoint");

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            ".",
            "--checkpoint",
            checkpointPath).ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("--checkpoint requires a native source option", result.Stderr);
        Assert.IsFalse(File.Exists(checkpointPath));
    }

    /// <summary>
    /// Verifies reset requires an explicit checkpoint path.
    /// </summary>
    [TestMethod]
    public async Task ScanCheckpointResetRequiresPath()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = WriteDockerArchive(temp.Path, "token-12345");

        CliResult result = await RunCliFromDirectoryAsync(
            temp.Path,
            "scan",
            "--docker-archive",
            archivePath,
            "--checkpoint-reset").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("--checkpoint-reset requires --checkpoint", result.Stderr);
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

    private static string WriteDockerArchive(string root, string content)
    {
        string archivePath = Path.Combine(root, "image.tar");
        byte[] layerBytes = TarTestData.CreateTarBytes(("app/settings.txt", Encoding.UTF8.GetBytes(content)));
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("manifest.json", Encoding.UTF8.GetBytes("""[{"Layers":["layer/layer.tar"]}]""")),
                ("layer/layer.tar", layerBytes)));
        return archivePath;
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
