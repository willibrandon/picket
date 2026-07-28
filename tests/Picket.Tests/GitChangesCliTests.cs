using System.Diagnostics;
using System.Text.Json;

namespace Picket.Tests;

/// <summary>
/// Tests the native Git changes mode through the built CLI.
/// </summary>
[TestClass]
public sealed class GitChangesCliTests
{
    private const int NativeOperationalExitCode = 2;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies mixed index and working-tree findings merge by occurrence while unique
    /// findings retain state-specific provenance and working-tree coordinates.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanMergesSharedFindingsAndPreservesUniqueSnapshots()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        string sourcePath = Path.Combine(root.Path, "source.txt");
        File.WriteAllText(sourcePath, "base\n");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "token-111\nindex token-222\n");
        await RunGitCommandAsync(root.Path, "add", "source.txt").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "leading line\ntoken-111\nworktree token-333\n");

        CliResult result = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        JsonElement findings = document.RootElement.GetProperty("findings");
        Assert.AreEqual(JsonValueKind.Array, findings.ValueKind);
        Assert.AreEqual(3, findings.GetArrayLength());
        Dictionary<string, JsonElement> bySecret = findings
            .EnumerateArray()
            .ToDictionary(
                finding => finding.GetProperty("secret").GetString()!,
                finding => finding.Clone(),
                StringComparer.Ordinal);
        Assert.AreEqual("git-index+worktree", GetProvenanceType(bySecret["token-111"]));
        Assert.AreEqual(2, bySecret["token-111"].GetProperty("startLine").GetInt32());
        Assert.AreEqual("git-index", GetProvenanceType(bySecret["token-222"]));
        Assert.AreEqual("git-worktree", GetProvenanceType(bySecret["token-333"]));
        Assert.AreEqual("source.txt", bySecret["token-111"].GetProperty("file").GetString());
    }

    /// <summary>
    /// Verifies repeated copies of the same token are paired by occurrence instead of
    /// being collapsed to one finding.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanPreservesRepeatedFindingOccurrences()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        string sourcePath = Path.Combine(root.Path, "source.txt");
        File.WriteAllText(sourcePath, "base\n");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "token-111\ntoken-111\n");
        await RunGitCommandAsync(root.Path, "add", "source.txt").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "leading\ntoken-111\ntoken-111\n");

        CliResult result = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        JsonElement findings = document.RootElement.GetProperty("findings");
        Assert.AreEqual(2, findings.GetArrayLength());
        int[] lines = [.. findings.EnumerateArray().Select(finding => finding.GetProperty("startLine").GetInt32())];
        string[] provenance = [.. findings.EnumerateArray().Select(GetProvenanceType)];
        Assert.AreEqual(2, lines[0]);
        Assert.AreEqual(3, lines[1]);
        Assert.IsEmpty(provenance.Where(value => !value.Equals("git-index+worktree", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Verifies native Git changes cannot be combined with another source provider.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanRejectsAnotherSourceProvider()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            "--github-repository",
            "owner/repository").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.Contains("scan accepts only one native source provider at a time", result.Stderr);
    }

    /// <summary>
    /// Verifies an invalid working-tree path produces a concise native operational error.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanReportsInvalidRepositoryWithoutStackTrace()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync(root.Path, "scan", "--git-changes", ".").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, result.ExitCode);
        Assert.Contains("path is not inside a Git working tree", result.Stderr);
        Assert.DoesNotContain("Unhandled exception", result.Stderr);
        Assert.DoesNotContain(" at Picket.", result.Stderr);
    }

    /// <summary>
    /// Verifies native Git changes load the selected root's .picketignore and suppress a
    /// copied stable finding fingerprint.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanLoadsRootPicketIgnore()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "source.txt"), "token-111\n");

        CliResult first = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(1, first.ExitCode);
        using JsonDocument firstDocument = JsonDocument.Parse(first.Stdout);
        JsonElement firstFinding = Assert.ContainsSingle(
            firstDocument.RootElement.GetProperty("findings").EnumerateArray());
        string fingerprint = firstFinding.GetProperty("fingerprint").GetString()!;
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), string.Concat(fingerprint, "\n"));

        CliResult second = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(0, second.ExitCode);
        using JsonDocument secondDocument = JsonDocument.Parse(second.Stdout);
        Assert.AreEqual(0, secondDocument.RootElement.GetProperty("findings").GetArrayLength());
    }

    /// <summary>
    /// Verifies --no-ignore includes Git-ignored untracked files in the aggregate scan.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesScanNoIgnoreIncludesGitIgnoredUntrackedFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "ignored.txt\n");
        await RunGitCommandAsync(root.Path, "add", ".gitignore").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-111\n");

        CliResult ignored = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);
        CliResult included = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--no-ignore",
            "--config",
            configPath,
            "--report-format",
            "json",
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(0, ignored.ExitCode);
        using JsonDocument ignoredDocument = JsonDocument.Parse(ignored.Stdout);
        Assert.AreEqual(0, ignoredDocument.RootElement.GetProperty("findings").GetArrayLength());
        Assert.AreEqual(1, included.ExitCode);
        using JsonDocument includedDocument = JsonDocument.Parse(included.Stdout);
        JsonElement finding = Assert.ContainsSingle(
            includedDocument.RootElement.GetProperty("findings").EnumerateArray());
        Assert.AreEqual("ignored.txt", finding.GetProperty("file").GetString());
        Assert.AreEqual("git-untracked", GetProvenanceType(finding));
    }

    /// <summary>
    /// Verifies checkpoint identity includes Git state provenance even when path and
    /// content bytes remain unchanged.
    /// </summary>
    [TestMethod]
    public async Task NativeGitChangesCheckpointRejectsChangedGitStateProvenance()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        string sourcePath = Path.Combine(root.Path, "source.txt");
        File.WriteAllText(sourcePath, "base\n");
        await RunGitCommandAsync(root.Path, "add", "source.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "token-111\n");
        await RunGitCommandAsync(root.Path, "add", "source.txt").ConfigureAwait(false);
        string checkpointPath = Path.Combine(root.Path, "scan.checkpoint");

        CliResult retained = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--checkpoint",
            checkpointPath,
            "--report-format",
            "jsonl",
            "--report-path",
            root.Path).ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "reset", "HEAD", "--", "source.txt").ConfigureAwait(false);
        CliResult changed = await RunCliAsync(
            root.Path,
            "scan",
            "--git-changes",
            ".",
            "--config",
            configPath,
            "--checkpoint",
            checkpointPath,
            "--report-format",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(NativeOperationalExitCode, retained.ExitCode);
        Assert.Contains("failed to write report", retained.Stderr);
        Assert.IsTrue(File.Exists(checkpointPath));
        Assert.AreEqual(NativeOperationalExitCode, changed.ExitCode);
        Assert.Contains(
            "checkpoint does not match the current scan or source snapshot",
            changed.Stderr,
            StringComparison.OrdinalIgnoreCase);
        Assert.IsTrue(File.Exists(checkpointPath));
    }

    /// <summary>
    /// Verifies the strict staged compatibility command does not begin scanning unstaged
    /// or untracked files when native Git changes support is enabled.
    /// </summary>
    [TestMethod]
    public async Task CompatibilityStagedScanRemainsStagedOnly()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string configPath = WriteTokenConfig(root.Path);
        string sourcePath = Path.Combine(root.Path, "source.txt");
        File.WriteAllText(sourcePath, "clean\n");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(sourcePath, "token-111\n");
        File.WriteAllText(Path.Combine(root.Path, "untracked.txt"), "token-222\n");

        CliResult result = await RunCliAsync(
            root.Path,
            "git",
            ".",
            "--staged",
            "--config",
            configPath,
            "--report-path",
            "-").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout.ReplaceLineEndings("\n"));
        Assert.Contains("no leaks found", result.Stderr);
    }

    /// <summary>
    /// Verifies command help explains the complete native Git state selection.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHelpDescribesGitChangesMode()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync(root.Path, "scan", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("--git-changes", result.Stdout);
        Assert.Contains("staged, unstaged, and untracked non-ignored changes", result.Stdout);
    }

    private static string GetProvenanceType(JsonElement finding)
    {
        return finding.GetProperty("provenance").GetProperty("type").GetString()!;
    }

    private async Task InitializeGitRepositoryAsync(string root)
    {
        await RunGitCommandAsync(root, "init").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "commit.gpgsign", "false").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.name", "Picket Test").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.email", "picket@example.com").ConfigureAwait(false);
    }

    private async Task<string> RunGitCommandAsync(string workingDirectory, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo("git")
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

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Assert.Fail($"git {string.Join(' ', arguments)} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    private async Task<CliResult> RunCliAsync(string workingDirectory, params string[] arguments)
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
            description = "test token"
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

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
