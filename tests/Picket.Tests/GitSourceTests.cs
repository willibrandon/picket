using Picket.Sources;
using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipes;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitSource" />.
/// </summary>
[TestClass]
public sealed class GitSourceTests
{
    /// <summary>
    /// Gets or sets the current test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

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
    /// Verifies that recognized Git diagnostics are emitted before the standard error stream closes.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ReadGitStandardErrorStreamsRecognizedWarnings()
    {
        const string FirstWarning = "warning: exhaustive rename detection was skipped due to too many files.";
        const string RemainingWarnings = """
            warning: inexact rename detection was skipped due to too many files.
            warning: you may want to set your diff.renameLimit variable to at least 2123 and retry the command.
            Auto packing the repository in background for optimum performance.
            See "git help gc" for manual housekeeping.

            """;
        string pipeName = string.Concat("pgs-", Guid.NewGuid().ToString("N")[..12]);
        using var writer = new NamedPipeServerStream(
            pipeName,
            PipeDirection.Out,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var reader = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.In,
            PipeOptions.Asynchronous);
        Task connectionTask = writer.WaitForConnectionAsync(TestContext.CancellationToken);
        await reader.ConnectAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await connectionTask.ConfigureAwait(false);
        using var stderr = new StreamReader(reader, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var firstWarningReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var warnings = new List<string>();
        Task<string> readTask = GitSource.ReadGitStandardErrorAsync(
            stderr,
            warning =>
            {
                warnings.Add(warning);
                firstWarningReceived.TrySetResult();
            });

        await writer.WriteAsync(
            Encoding.UTF8.GetBytes(string.Concat(FirstWarning, '\n')),
            TestContext.CancellationToken).ConfigureAwait(false);
        await writer.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await firstWarningReceived.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(readTask.IsCompleted);

        await writer.WriteAsync(
            Encoding.UTF8.GetBytes(RemainingWarnings.ReplaceLineEndings("\n")),
            TestContext.CancellationToken).ConfigureAwait(false);
        await writer.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);
        writer.Close();
        string errors = await readTask.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(errors);
        Assert.HasCount(5, warnings);
        Assert.AreEqual(FirstWarning, warnings[0]);
        Assert.Contains("diff.renameLimit", warnings[2]);
        Assert.StartsWith("Auto packing", warnings[3]);
        Assert.StartsWith("See \"git help gc\"", warnings[4]);
    }

    /// <summary>
    /// Verifies that unrecognized Git diagnostics remain errors instead of being downgraded to warnings.
    /// </summary>
    [TestMethod]
    public async Task ReadGitStandardErrorReturnsUnrecognizedLines()
    {
        const string Input = """
            fatal: unable to read object
            warning: exhaustive rename detection was skipped due to too many files.
            fatal: invalid object
            """;
        using var stderr = new StringReader(Input.ReplaceLineEndings("\n"));
        var warnings = new List<string>();

        string errors = await GitSource.ReadGitStandardErrorAsync(stderr, warnings.Add).ConfigureAwait(false);

        Assert.HasCount(1, warnings);
        Assert.Contains("exhaustive rename detection", warnings[0]);
        Assert.AreEqual(
            "fatal: unable to read object\nfatal: invalid object",
            errors);
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

    /// <summary>
    /// Verifies that patch parsing yields a completed fragment before consuming later patch bytes.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ParsePatchYieldsFragmentBeforeReadingFollowingPatchBytes()
    {
        const string FirstCommit = """
            commit 0000000000000000000000000000000000000001
            Author: Picket Test <picket@example.com>
            Date: 2024-01-01T00:00:00Z

                first

            diff --git a/first.txt b/first.txt
            --- /dev/null
            +++ b/first.txt
            @@ -0,0 +1 @@
            +token-first
            commit 0000000000000000000000000000000000000002

            """;
        const string SecondCommit = """
            Author: Picket Test <picket@example.com>
            Date: 2024-01-02T00:00:00Z

                second

            diff --git a/second.txt b/second.txt
            --- /dev/null
            +++ b/second.txt
            @@ -0,0 +1 @@
            +token-second

            """;
        string pipeName = string.Concat("pgs-", Guid.NewGuid().ToString("N")[..12]);
        using var writer = new NamedPipeServerStream(
            pipeName,
            PipeDirection.Out,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var reader = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.In,
            PipeOptions.Asynchronous);
        Task connectionTask = writer.WaitForConnectionAsync(TestContext.CancellationToken);
        await reader.ConnectAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await connectionTask.ConfigureAwait(false);
        var firstFragmentYielded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int secondHalfWritten = 0;
        Task writeTask = Task.Run(
            async () =>
            {
                await writer.WriteAsync(
                    Encoding.UTF8.GetBytes(FirstCommit.ReplaceLineEndings("\n")),
                    TestContext.CancellationToken).ConfigureAwait(false);
                await writer.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);
                await firstFragmentYielded.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
                Interlocked.Exchange(ref secondHalfWritten, 1);
                await writer.WriteAsync(
                    Encoding.UTF8.GetBytes(SecondCommit.ReplaceLineEndings("\n")),
                    TestContext.CancellationToken).ConfigureAwait(false);
                await writer.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);
                writer.Close();
            },
            TestContext.CancellationToken);
        var fragments = new List<GitPatchFragment>();

        int commitCount = GitSource.ParsePatch(
            reader,
            new GitScanOptions("."),
            fragment =>
            {
                if (fragments.Count == 0)
                {
                    Assert.AreEqual(0, Volatile.Read(ref secondHalfWritten));
                    firstFragmentYielded.SetResult();
                }

                fragments.Add(fragment);
            });
        await writeTask.ConfigureAwait(false);

        Assert.HasCount(2, fragments);
        Assert.AreEqual(2, commitCount);
        Assert.AreEqual("first.txt", fragments[0].FilePath);
        Assert.AreEqual("second.txt", fragments[1].FilePath);
    }

    /// <summary>
    /// Verifies that commit accounting includes modified-file hunks with no added lines.
    /// </summary>
    [TestMethod]
    public void ParsePatchCountsCommitWithDeletionOnlyHunk()
    {
        byte[] patch = Encoding.UTF8.GetBytes(
            """
            commit 0000000000000000000000000000000000000001
            Author: Picket Test <picket@example.com>
            Date: 2024-01-01T00:00:00Z

                remove line

            diff --git a/modified.txt b/modified.txt
            --- a/modified.txt
            +++ b/modified.txt
            @@ -1 +0,0 @@
            -removed
            commit 0000000000000000000000000000000000000002
            Author: Picket Test <picket@example.com>
            Date: 2024-01-02T00:00:00Z

                add line

            diff --git a/added.txt b/added.txt
            --- /dev/null
            +++ b/added.txt
            @@ -0,0 +1 @@
            +token-added

            """.ReplaceLineEndings("\n"));
        using var stream = new MemoryStream(patch, writable: false);
        var fragments = new List<GitPatchFragment>();

        int commitCount = GitSource.ParsePatch(stream, new GitScanOptions("."), fragments.Add);

        Assert.AreEqual(2, commitCount);
        Assert.HasCount(1, fragments);
        Assert.AreEqual("added.txt", fragments[0].FilePath);
    }

    /// <summary>
    /// Verifies that Gitleaks no-newline markers remove the synthetic patch line ending.
    /// </summary>
    [TestMethod]
    public void ParsePatchRemovesAddedLineEndingBeforeNoNewlineMarker()
    {
        byte[] patch = Encoding.UTF8.GetBytes(
            """
            commit 0000000000000000000000000000000000000001
            Author: Picket Test <picket@example.com>
            Date: 2024-01-01T00:00:00Z

                no final newline

            diff --git a/secret.txt b/secret.txt
            --- /dev/null
            +++ b/secret.txt
            @@ -0,0 +1 @@
            +token-without-newline
            \ No newline at end of file

            """.ReplaceLineEndings("\n"));
        using var stream = new MemoryStream(patch, writable: false);

        List<GitPatchFragment> fragments = GitSource.ParsePatch(stream, new GitScanOptions("."));

        Assert.HasCount(1, fragments);
        Assert.IsTrue(fragments[0].Input.Span.SequenceEqual("token-without-newline"u8));
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
