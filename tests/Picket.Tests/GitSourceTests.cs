using Picket.Sources;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitSource" />.
/// </summary>
[TestClass]
public sealed class GitSourceTests
{
    /// <summary>
    /// Verifies that git history enumeration expands zip archive blobs when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public async Task EnumerateExpandsZipArchiveBlobWhenDepthEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(Path.Combine(root.Path, "secrets.zip"), ("nested/secret.txt", "token-12345"));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        IReadOnlyList<GitPatchFragment> disabled = GitSource.Enumerate(new GitScanOptions(root.Path));
        IReadOnlyList<GitPatchFragment> enabled = GitSource.Enumerate(new GitScanOptions(root.Path, maxArchiveDepth: 1));

        Assert.IsEmpty(disabled);
        Assert.HasCount(1, enabled);
        GitPatchFragment fragment = enabled[0];
        Assert.AreEqual("secrets.zip!nested/secret.txt", fragment.FilePath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(fragment.Input.Span));
        Assert.AreEqual(1, fragment.StartLine);
        Assert.AreEqual(commit, fragment.Commit);
        Assert.AreEqual("Picket Test", fragment.Author);
        Assert.AreEqual("picket@example.com", fragment.Email);
        Assert.AreEqual("add archive", fragment.Message);
    }

    /// <summary>
    /// Verifies that git history enumeration expands tar archive blobs when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public async Task EnumerateExpandsTarArchiveBlobWhenDepthEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllBytes(Path.Combine(root.Path, "secrets.tar"), TarTestData.CreateTarBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("token-12345"))));
        await RunGitCommandAsync(root.Path, "add", "secrets.tar").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add tar archive").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        IReadOnlyList<GitPatchFragment> disabled = GitSource.Enumerate(new GitScanOptions(root.Path));
        IReadOnlyList<GitPatchFragment> enabled = GitSource.Enumerate(new GitScanOptions(root.Path, maxArchiveDepth: 1));

        Assert.IsEmpty(disabled);
        Assert.HasCount(1, enabled);
        GitPatchFragment fragment = enabled[0];
        Assert.AreEqual("secrets.tar!nested/secret.txt", fragment.FilePath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(fragment.Input.Span));
        Assert.AreEqual(commit, fragment.Commit);
    }

    /// <summary>
    /// Verifies that nested git archive traversal honors the configured archive depth.
    /// </summary>
    [TestMethod]
    public async Task EnumerateHonorsZipArchiveBlobDepth()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        byte[] innerArchive = CreateZipBytes(("secret.txt", Encoding.UTF8.GetBytes("token-12345")));
        File.WriteAllBytes(Path.Combine(root.Path, "outer.zip"), CreateZipBytes(("inner.zip", innerArchive)));
        await RunGitCommandAsync(root.Path, "add", "outer.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add nested archive").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> shallow = GitSource.Enumerate(new GitScanOptions(root.Path, maxArchiveDepth: 1));
        IReadOnlyList<GitPatchFragment> recursive = GitSource.Enumerate(new GitScanOptions(root.Path, maxArchiveDepth: 2));
        string[] shallowPaths = [.. shallow.Select(fragment => fragment.FilePath)];
        string[] recursivePaths = [.. recursive.Select(fragment => fragment.FilePath)];

        Assert.DoesNotContain("outer.zip!inner.zip!secret.txt", shallowPaths);
        Assert.Contains("outer.zip!inner.zip!secret.txt", recursivePaths);
    }

    /// <summary>
    /// Verifies that git archive enumeration honors the configured entry-count safety cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateHonorsArchiveBlobEntryLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("first.txt", "token-12345"),
            ("second.txt", "token-23456"));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);
        var warnings = new List<string>();

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(
            root.Path,
            maxArchiveDepth: 1,
            maxArchiveEntries: 1,
            warningSink: warnings.Add));
        string[] paths = [.. fragments.Select(fragment => fragment.FilePath)];

        Assert.HasCount(1, fragments);
        Assert.Contains("secrets.zip!first.txt", paths);
        Assert.DoesNotContain("secrets.zip!second.txt", paths);
        Assert.HasCount(1, warnings);
        Assert.Contains("archive entry limit reached after 1 entries while reading secrets.zip", warnings[0]);
    }

    /// <summary>
    /// Verifies that git archive enumeration honors the configured decompressed byte safety cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateHonorsArchiveBlobByteLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("first.txt", "token-12345"),
            ("second.txt", "token-23456"));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);
        var warnings = new List<string>();

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(
            root.Path,
            maxArchiveDepth: 1,
            maxArchiveBytes: 11,
            warningSink: warnings.Add));
        string[] paths = [.. fragments.Select(fragment => fragment.FilePath)];

        Assert.HasCount(1, fragments);
        Assert.Contains("secrets.zip!first.txt", paths);
        Assert.DoesNotContain("secrets.zip!second.txt", paths);
        Assert.HasCount(1, warnings);
        Assert.Contains("archive byte limit reached while reading secrets.zip", warnings[0]);
    }

    /// <summary>
    /// Verifies that git archive enumeration honors the configured compression-ratio safety cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateHonorsArchiveBlobCompressionRatioLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteCompressedZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("secret.txt", string.Concat("token-12345\n", new string('!', 8192))));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);
        var warnings = new List<string>();

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(
            root.Path,
            maxArchiveDepth: 1,
            warningSink: warnings.Add,
            maxArchiveCompressionRatio: 1));

        Assert.IsEmpty(fragments);
        Assert.HasCount(1, warnings);
        Assert.Contains("archive compression ratio limit reached while reading secrets.zip", warnings[0]);
    }

    /// <summary>
    /// Verifies that staged git enumeration expands zip archive blobs from the index.
    /// </summary>
    [TestMethod]
    public async Task EnumerateExpandsStagedZipArchiveBlobWhenDepthEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(Path.Combine(root.Path, "staged.zip"), ("secret.txt", "token-12345"));
        await RunGitCommandAsync(root.Path, "add", "staged.zip").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(root.Path, staged: true, maxArchiveDepth: 1));

        Assert.HasCount(1, fragments);
        GitPatchFragment fragment = fragments[0];
        Assert.AreEqual("staged.zip!secret.txt", fragment.FilePath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(fragment.Input.Span));
        Assert.AreEqual(string.Empty, fragment.Commit);
    }

    /// <summary>
    /// Verifies that added git patch lines beginning with two plus signs are preserved.
    /// </summary>
    [TestMethod]
    public async Task EnumerateCapturesAddedLinesBeginningWithDoublePlus()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "++secret-token\n++ secret-token\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add plus-prefixed secret").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(root.Path));

        Assert.HasCount(1, fragments);
        Assert.AreEqual("secret.txt", fragments[0].FilePath);
        Assert.AreEqual("++secret-token\n++ secret-token\n", Encoding.UTF8.GetString(fragments[0].Input.Span));
        Assert.AreEqual(1, fragments[0].StartLine);
    }

    /// <summary>
    /// Verifies that git-quoted UTF-8 paths are decoded before findings are mapped.
    /// </summary>
    [TestMethod]
    public async Task EnumerateDecodesGitQuotedUtf8Paths()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        const string FileName = "caf\u00e9.txt";
        File.WriteAllText(Path.Combine(root.Path, FileName), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", FileName).ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add unicode path").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(root.Path));

        Assert.HasCount(1, fragments);
        Assert.AreEqual(FileName, fragments[0].FilePath);
    }

    /// <summary>
    /// Verifies that raw invalid UTF-8 bytes in added lines are not replaced before matching.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePreservesInvalidUtf8PatchBytes()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        byte[] content = [0xFF, .. "token-12345\n"u8.ToArray()];
        File.WriteAllBytes(Path.Combine(root.Path, "invalid.txt"), content);
        await RunGitCommandAsync(root.Path, "add", "invalid.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add invalid utf8").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(root.Path));

        Assert.HasCount(1, fragments);
        Assert.AreEqual(0xFF, fragments[0].Input.Span[0]);
        Assert.IsTrue(fragments[0].Input.Span[1..].SequenceEqual("token-12345\n"u8));
    }

    /// <summary>
    /// Verifies that CRLF bytes and the final line terminator remain in added patch fragments.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePreservesCrlfPatchLineTerminators()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllBytes(Path.Combine(root.Path, "crlf.txt"), "first\r\nsecond\r\n"u8.ToArray());
        await RunGitCommandAsync(root.Path, "add", "crlf.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add crlf").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(root.Path));

        Assert.HasCount(1, fragments);
        Assert.IsTrue(fragments[0].Input.Span.SequenceEqual("first\r\nsecond\r\n"u8));
    }

    /// <summary>
    /// Verifies that git enumeration stops cleanly when cancellation is already requested.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task EnumerateStopsWhenCancellationIsRequested()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);

        IReadOnlyList<GitPatchFragment> fragments = GitSource.Enumerate(new GitScanOptions(
            root.Path,
            isCancellationRequested: () => true));

        Assert.IsEmpty(fragments);
    }

    /// <summary>
    /// Verifies unsafe git log options are rejected before git can create output files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRejectsUnsafeLogOptionsWithoutCreatingOutput()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string outputPath = Path.Combine(root.Path, "git-output.txt");

        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => GitSource.Enumerate(new GitScanOptions(root.Path, logOptions: $"--output={outputPath}")));

        Assert.Contains("unsafe git log option: --output=", exception.Message);
        Assert.IsFalse(File.Exists(outputPath));
    }

    /// <summary>
    /// Verifies a malformed hunk does not abort parsing of a later valid patch fragment.
    /// </summary>
    [TestMethod]
    public void ParsePatchSkipsMalformedHunkAndResumesAtNextDiff()
    {
        byte[] patch = Encoding.UTF8.GetBytes(
            """
            commit 0000000000000000000000000000000000000001
            Author: Picket Test <picket@example.com>
            Date: 2024-01-01T00:00:00Z

                malformed then valid

            diff --git a/broken.txt b/broken.txt
            --- /dev/null
            +++ b/broken.txt
            @@ -0,0 +2147483648 @@
            +token-broken
            unexpected patch metadata
            diff --git a/valid.txt b/valid.txt
            --- /dev/null
            +++ b/valid.txt
            @@ -0,0 +7 @@
            +token-valid
            """);
        using var stream = new MemoryStream(patch, writable: false);

        List<GitPatchFragment> fragments = GitSource.ParsePatch(stream, new GitScanOptions("."));

        Assert.HasCount(1, fragments);
        Assert.AreEqual("valid.txt", fragments[0].FilePath);
        Assert.AreEqual(7, fragments[0].StartLine);
        Assert.AreEqual("token-valid", Encoding.UTF8.GetString(fragments[0].Input.Span));
    }

    private static async Task InitializeGitRepositoryAsync(string root)
    {
        await RunGitCommandAsync(root, "init").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.name", "Picket Test").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.email", "picket@example.com").ConfigureAwait(false);
    }

    private static async Task<string> RunGitCommandAsync(string workingDirectory, params string[] arguments)
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
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Assert.Fail($"git {string.Join(' ', arguments)} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    private static void WriteZipFile(string path, params (string Name, string Content)[] entries)
    {
        File.WriteAllBytes(path, CreateZipBytes([.. entries.Select(entry => (entry.Name, Encoding.UTF8.GetBytes(entry.Content)))]));
    }

    private static void WriteCompressedZipFile(string path, params (string Name, string Content)[] entries)
    {
        File.WriteAllBytes(path, CreateZipBytes(CompressionLevel.SmallestSize, [.. entries.Select(entry => (entry.Name, Encoding.UTF8.GetBytes(entry.Content)))]));
    }

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        return CreateZipBytes(CompressionLevel.NoCompression, entries);
    }

    private static byte[] CreateZipBytes(CompressionLevel compressionLevel, params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, compressionLevel);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }

}
