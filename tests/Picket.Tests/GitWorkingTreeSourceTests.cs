using Picket.Sources;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitWorkingTreeSource" />.
/// </summary>
[TestClass]
public sealed class GitWorkingTreeSourceTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies staged, unstaged, and untracked snapshots are enumerated while unchanged,
    /// deleted, and Git-ignored paths are excluded.
    /// </summary>
    [TestMethod]
    public async Task EnumerateIncludesAllRelevantGitChangeStates()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "ignored.txt\n");
        File.WriteAllText(Path.Combine(root.Path, "deleted.txt"), "deleted-base");
        File.WriteAllText(Path.Combine(root.Path, "mixed.txt"), "mixed-base");
        File.WriteAllText(Path.Combine(root.Path, "unchanged.txt"), "unchanged");
        File.WriteAllText(Path.Combine(root.Path, "unstaged.txt"), "unstaged-base");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);

        File.Delete(Path.Combine(root.Path, "deleted.txt"));
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "ignored-secret");
        File.WriteAllText(Path.Combine(root.Path, "mixed.txt"), "mixed-index");
        await RunGitCommandAsync(root.Path, "add", "mixed.txt").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "mixed.txt"), "mixed-worktree");
        File.WriteAllText(Path.Combine(root.Path, "staged.txt"), "staged");
        await RunGitCommandAsync(root.Path, "add", "staged.txt").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "unstaged.txt"), "unstaged");
        File.WriteAllText(Path.Combine(root.Path, "untracked.txt"), "untracked");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(root.Path));

        Assert.HasCount(5, files);
        AssertSource(files[0], "mixed.txt", "git-index", "mixed-index");
        AssertSource(files[1], "mixed.txt", "git-worktree", "mixed-worktree");
        AssertSource(files[2], "staged.txt", "git-index", "staged");
        AssertSource(files[3], "unstaged.txt", "git-worktree", "unstaged");
        AssertSource(files[4], "untracked.txt", "git-untracked", "untracked");
    }

    /// <summary>
    /// Verifies a nested scan root and global path filtering retain repository-relative paths.
    /// </summary>
    [TestMethod]
    public async Task EnumerateLimitsChangesToSelectedPathAndPathFilter()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string nestedPath = Directory.CreateDirectory(Path.Combine(root.Path, "nested")).FullName;
        File.WriteAllText(Path.Combine(nestedPath, "allowed.txt"), "base");
        File.WriteAllText(Path.Combine(nestedPath, "excluded.txt"), "base");
        File.WriteAllText(Path.Combine(root.Path, "outside.txt"), "base");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(nestedPath, "allowed.txt"), "allowed-change");
        File.WriteAllText(Path.Combine(nestedPath, "excluded.txt"), "excluded-change");
        File.WriteAllText(Path.Combine(root.Path, "outside.txt"), "outside-change");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            nestedPath,
            isPathAllowed: static path => path.Equals("nested/excluded.txt", StringComparison.Ordinal)));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "nested/allowed.txt", "git-worktree", "allowed-change");
    }

    /// <summary>
    /// Verifies a file scan root limits enumeration to that repository-relative path.
    /// </summary>
    [TestMethod]
    public async Task EnumerateSupportsChangedFileRoot()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string selectedPath = Path.Combine(root.Path, "selected.txt");
        File.WriteAllText(selectedPath, "base");
        File.WriteAllText(Path.Combine(root.Path, "other.txt"), "base");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(selectedPath, "selected-change");
        File.WriteAllText(Path.Combine(root.Path, "other.txt"), "other-change");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(selectedPath));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "selected.txt", "git-worktree", "selected-change");
    }

    /// <summary>
    /// Verifies every Git snapshot honors the raw source byte cap before it is returned.
    /// </summary>
    [TestMethod]
    public async Task EnumerateAppliesTargetByteCapToEveryChangeState()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "unstaged.txt"), "base");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "staged.txt"), "staged-too-long");
        await RunGitCommandAsync(root.Path, "add", "staged.txt").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "unstaged.txt"), "unstaged-too-long");
        File.WriteAllText(Path.Combine(root.Path, "untracked.txt"), "untracked-too-long");
        var warnings = new List<string>();

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            root.Path,
            maxTargetBytes: 4,
            warningSink: warnings.Add));

        Assert.IsEmpty(files);
        Assert.HasCount(3, warnings);
        Assert.Contains("staged.txt", warnings[0]);
        Assert.Contains("unstaged.txt", warnings[1]);
        Assert.Contains("untracked.txt", warnings[2]);
    }

    /// <summary>
    /// Verifies archive entries from an index snapshot retain the index provenance.
    /// </summary>
    [TestMethod]
    public async Task EnumerateExpandsStagedArchiveWithIndexProvenance()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllBytes(
            Path.Combine(root.Path, "staged.zip"),
            CreateZipBytes(("nested/secret.txt", "token-12345"u8.ToArray())));
        await RunGitCommandAsync(root.Path, "add", "staged.zip").ConfigureAwait(false);

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            root.Path,
            maxArchiveDepth: 1));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "staged.zip!nested/secret.txt", "git-index", "token-12345");
    }

    /// <summary>
    /// Verifies NUL-delimited Git output preserves spaces and non-ASCII path text.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePreservesSpecialGitPaths()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string directoryPath = Directory.CreateDirectory(Path.Combine(root.Path, "folder with spaces")).FullName;
        string filePath = Path.Combine(directoryPath, "unicod\u00e9.txt");
        File.WriteAllText(filePath, "untracked");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(root.Path));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "folder with spaces/unicod\u00e9.txt", "git-untracked", "untracked");
    }

    /// <summary>
    /// Verifies callers can explicitly include Git-ignored untracked files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCanIncludeGitIgnoredUntrackedFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "ignored.txt\n");
        await RunGitCommandAsync(root.Path, "add", ".gitignore").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "ignored");

        IReadOnlyList<SourceFile> excluded = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            root.Path));
        IReadOnlyList<SourceFile> included = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            root.Path,
            respectGitIgnoreFiles: false));

        Assert.IsEmpty(excluded);
        SourceFile file = Assert.ContainsSingle(included);
        AssertSource(file, "ignored.txt", "git-untracked", "ignored");
    }

    /// <summary>
    /// Verifies NUL-delimited Git output does not split a valid newline-bearing Unix path.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    public async Task EnumeratePreservesNewlineInUnixPath()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "line\nbreak.txt"), "untracked");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(root.Path));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "line\nbreak.txt", "git-untracked", "untracked");
    }

    /// <summary>
    /// Verifies a tracked file changed to a symbolic link is scanned as link text without
    /// following the target.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    public async Task EnumerateIncludesTypeChangedSymbolicLink()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string linkPath = Path.Combine(root.Path, "link.txt");
        File.WriteAllText(linkPath, "regular");
        File.WriteAllText(Path.Combine(root.Path, "target.txt"), "target-secret");
        await RunGitCommandAsync(root.Path, "add", ".").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.Delete(linkPath);
        File.CreateSymbolicLink(linkPath, "target.txt");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            linkPath));

        SourceFile file = Assert.ContainsSingle(files);
        AssertSource(file, "link.txt", "git-worktree", "target.txt");
    }

    /// <summary>
    /// Verifies repository selection works when a caller path contains a symbolic-link
    /// ancestor such as macOS /var resolving to /private/var.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    public async Task EnumerateSupportsRepositoryPathThroughSymbolicLinkAncestor()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "untracked.txt"), "token-111\n");
        string aliasPath = Path.Combine(
            Path.GetDirectoryName(root.Path)!,
            string.Concat("picket-git-alias-", Guid.NewGuid().ToString("N")));
        Directory.CreateSymbolicLink(aliasPath, root.Path);
        try
        {
            IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(
                new GitWorkingTreeScanOptions(aliasPath));

            SourceFile file = Assert.ContainsSingle(files);
            AssertSource(file, "untracked.txt", "git-untracked", "token-111\n");
        }
        finally
        {
            Directory.Delete(aliasPath);
        }
    }

    /// <summary>
    /// Verifies pre-requested cancellation performs no source enumeration.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task EnumerateStopsWhenCancellationIsRequested()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "untracked.txt"), "token-12345");

        IReadOnlyList<SourceFile> files = GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(
            root.Path,
            isCancellationRequested: static () => true));

        Assert.IsEmpty(files);
    }

    /// <summary>
    /// Verifies a non-repository root reports a concise source error.
    /// </summary>
    [TestMethod]
    public void EnumerateRejectsPathOutsideGitWorkingTree()
    {
        using TempDirectory root = TempDirectory.Create();

        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => GitWorkingTreeSource.Enumerate(new GitWorkingTreeScanOptions(root.Path)));

        Assert.Contains("not inside a Git working tree", exception.Message);
        string normalizedMessage = exception.Message.Replace("\r\n", "\n", StringComparison.Ordinal);
        Assert.DoesNotContain("\n   at ", normalizedMessage);
    }

    private static void AssertSource(SourceFile file, string path, string provenanceType, string content)
    {
        Assert.AreEqual(path, file.DisplayPath);
        Assert.AreEqual(provenanceType, file.ProvenanceType);
        Assert.AreEqual(content, Encoding.UTF8.GetString(file.ReadAllBytes()));
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

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }
}
