using Picket.Engine;
using Picket.Store;
using System.Runtime.Versioning;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests authenticated remote scan checkpoint persistence.
/// </summary>
[TestClass]
public sealed class RemoteScanCheckpointTests
{
    private static readonly byte[] s_firstContent = Encoding.UTF8.GetBytes("first source content");
    private static readonly byte[] s_secondContent = Encoding.UTF8.GetBytes("second source content");
    private static readonly byte[] s_thirdContent = Encoding.UTF8.GetBytes("third source content");

    /// <summary>
    /// Verifies checkpoints restore every finding field without storing raw evidence as plaintext.
    /// </summary>
    [TestMethod]
    public void OpenRestoresEncryptedFindingState()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        Finding finding = CreateFinding("src/secret.txt", "raw-secret-value");

        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("src/secret.txt", "link/secret.txt", s_firstContent, [finding]);
        }

        string persisted = File.ReadAllText(path);
        Assert.DoesNotContain(finding.Secret, persisted);
        Assert.DoesNotContain(finding.Match, persisted);
        Assert.DoesNotContain(finding.Line, persisted);

        using RemoteScanCheckpoint restored = RemoteScanCheckpoint.Open(path, CreateKey());
        Assert.AreEqual(1, restored.CompletedFileCount);
        Assert.IsTrue(restored.TryRestoreFile(0, "src/secret.txt", "link/secret.txt", s_firstContent, out List<Finding>? findings));
        Assert.IsNotNull(findings);
        Assert.HasCount(1, findings);
        AssertFindingsEqual(finding, findings[0]);
    }

    /// <summary>
    /// Verifies a checkpoint cannot be reused for a different scanner or source manifest.
    /// </summary>
    [TestMethod]
    public void OpenRejectsDifferentCheckpointKey()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("src/secret.txt", string.Empty, s_firstContent, []);
        }

        RemoteScanCheckpointKey differentKey = new(new string('c', 64), new string('d', 64));
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(
            () => RemoteScanCheckpoint.Open(path, differentKey).Dispose());

        Assert.Contains("--checkpoint-reset", exception.Message);
    }

    /// <summary>
    /// Verifies an explicit reset replaces incompatible checkpoint state.
    /// </summary>
    [TestMethod]
    public void OpenResetReplacesDifferentCheckpointKey()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("src/secret.txt", string.Empty, s_firstContent, []);
        }

        RemoteScanCheckpointKey differentKey = new(new string('c', 64), new string('d', 64));
        using RemoteScanCheckpoint reset = RemoteScanCheckpoint.Open(path, differentKey, reset: true);

        Assert.AreEqual(0, reset.CompletedFileCount);
        Assert.IsFalse(reset.TryRestoreFile(0, "src/secret.txt", string.Empty, s_firstContent, out _));
    }

    /// <summary>
    /// Verifies authenticated records reject modifications.
    /// </summary>
    [TestMethod]
    public void OpenRejectsTamperedRecord()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("src/secret.txt", string.Empty, s_firstContent, []);
        }

        string[] lines = File.ReadAllLines(path);
        lines[2] = string.Concat(lines[2][..^1], lines[2][^1] == 'A' ? 'B' : 'A');
        File.WriteAllText(path, string.Concat(string.Join('\n', lines), "\n"));

        Assert.ThrowsExactly<InvalidDataException>(() => RemoteScanCheckpoint.Open(path, CreateKey()).Dispose());
    }

    /// <summary>
    /// Verifies record removal cannot move the low-water mark past omitted work.
    /// </summary>
    [TestMethod]
    public void OpenRejectsBrokenRecordChain()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);
            checkpoint.AppendCompletedFile("second.txt", string.Empty, s_secondContent, []);
            checkpoint.AppendCompletedFile("third.txt", string.Empty, s_thirdContent, []);
        }

        List<string> lines = [.. File.ReadAllLines(path)];
        lines.RemoveAt(3);
        File.WriteAllText(path, string.Concat(string.Join('\n', lines), "\n"));

        Assert.ThrowsExactly<InvalidDataException>(() => RemoteScanCheckpoint.Open(path, CreateKey()).Dispose());
    }

    /// <summary>
    /// Verifies a partially appended final record is treated as uncommitted work.
    /// </summary>
    [TestMethod]
    public void OpenIgnoresTruncatedCrashTail()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);
            checkpoint.AppendCompletedFile("second.txt", string.Empty, s_secondContent, []);
        }

        string persisted = File.ReadAllText(path);
        int lastRecord = persisted.LastIndexOf("record\t", StringComparison.Ordinal);
        File.WriteAllText(path, persisted[..(lastRecord + 20)]);

        using RemoteScanCheckpoint restored = RemoteScanCheckpoint.Open(path, CreateKey());
        Assert.AreEqual(1, restored.CompletedFileCount);
        Assert.IsTrue(restored.TryRestoreFile(0, "first.txt", string.Empty, s_firstContent, out List<Finding>? findings));
        Assert.IsNotNull(findings);
        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies restored entries are checked against the current file sequence.
    /// </summary>
    [TestMethod]
    public void TryRestoreFileRejectsChangedContent()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using (RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey()))
        {
            checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);
        }

        using RemoteScanCheckpoint restored = RemoteScanCheckpoint.Open(path, CreateKey());
        Assert.ThrowsExactly<InvalidDataException>(
            () => restored.TryRestoreFile(0, "first.txt", string.Empty, s_secondContent, out _));
    }

    /// <summary>
    /// Verifies concurrent writers cannot own the same checkpoint.
    /// </summary>
    [TestMethod]
    public void OpenRejectsConcurrentWriter()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using RemoteScanCheckpoint first = RemoteScanCheckpoint.Open(path, CreateKey());

        Assert.ThrowsExactly<IOException>(() => RemoteScanCheckpoint.Open(path, CreateKey()).Dispose());
    }

    /// <summary>
    /// Verifies checkpoint growth is bounded.
    /// </summary>
    [TestMethod]
    public void AppendCompletedFileEnforcesMaximumSize()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey(), maxBytes: 1_024);
        Finding finding = CreateFinding("secret.txt", new string('x', 2_048));

        Assert.ThrowsExactly<IOException>(
            () => checkpoint.AppendCompletedFile("secret.txt", string.Empty, s_firstContent, [finding]));
    }

    /// <summary>
    /// Verifies successful completion removes checkpoint state.
    /// </summary>
    [TestMethod]
    public void CompleteDeletesCheckpoint()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using var checkpoint = RemoteScanCheckpoint.Open(path, CreateKey());
        checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);

        bool completed = checkpoint.Complete();

        Assert.IsTrue(completed);
        Assert.IsFalse(File.Exists(path));
    }

    /// <summary>
    /// Verifies checkpoint and lock files are owner-only on Unix-like systems.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void OpenCreatesOwnerOnlyFilesOnUnix()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey());
        checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);

        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(path));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(string.Concat(path, ".lock")));
    }

    /// <summary>
    /// Verifies checkpoint and lock files are owner-only on Windows.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void OpenCreatesOwnerOnlyFilesOnWindows()
    {
        using TempDirectory root = TempDirectory.Create();
        string path = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        using RemoteScanCheckpoint checkpoint = RemoteScanCheckpoint.Open(path, CreateKey());
        checkpoint.AppendCompletedFile("first.txt", string.Empty, s_firstContent, []);

        WindowsAccessControlAssert.AllowsOnlyCurrentUser(path);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(string.Concat(path, ".lock"));
    }

    /// <summary>
    /// Verifies checkpoint state does not follow a symbolic-link path.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void OpenRejectsSymbolicLinkCheckpointPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string targetPath = System.IO.Path.Combine(root.Path, "target");
        string checkpointPath = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        File.WriteAllText(targetPath, "unchanged");
        File.CreateSymbolicLink(checkpointPath, targetPath);

        Assert.ThrowsExactly<IOException>(() => RemoteScanCheckpoint.Open(checkpointPath, CreateKey()).Dispose());
        Assert.AreEqual("unchanged", File.ReadAllText(targetPath));
    }

    /// <summary>
    /// Verifies checkpoint locking does not follow a symbolic-link path.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void OpenRejectsSymbolicLinkLockPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string targetPath = System.IO.Path.Combine(root.Path, "target");
        string checkpointPath = System.IO.Path.Combine(root.Path, "scan.checkpoint");
        File.WriteAllText(targetPath, "unchanged");
        File.CreateSymbolicLink(string.Concat(checkpointPath, ".lock"), targetPath);

        Assert.ThrowsExactly<IOException>(() => RemoteScanCheckpoint.Open(checkpointPath, CreateKey()).Dispose());
        Assert.AreEqual("unchanged", File.ReadAllText(targetPath));
    }

    private static RemoteScanCheckpointKey CreateKey()
    {
        return new RemoteScanCheckpointKey(new string('a', 64), new string('b', 64));
    }

    private static Finding CreateFinding(string file, string secret)
    {
        return new Finding(
            "rule-id",
            "description",
            2,
            3,
            4,
            5,
            string.Concat("match:", secret),
            secret,
            file,
            "link/secret.txt",
            "0123456789abcdef",
            4.25,
            "Brandon Williams",
            "author@example.test",
            "2026-07-10T00:00:00Z",
            "commit message",
            ["provider", "token"],
            "fingerprint",
            string.Concat("line:", secret),
            "https://example.test/source#L2",
            new string('c', 64),
            new string('d', 64),
            "structurally-valid",
            new string('e', 64),
            ["base64"]);
    }

    private static void AssertFindingsEqual(Finding expected, Finding actual)
    {
        Assert.AreEqual(expected.RuleID, actual.RuleID);
        Assert.AreEqual(expected.Description, actual.Description);
        Assert.AreEqual(expected.StartLine, actual.StartLine);
        Assert.AreEqual(expected.EndLine, actual.EndLine);
        Assert.AreEqual(expected.StartColumn, actual.StartColumn);
        Assert.AreEqual(expected.EndColumn, actual.EndColumn);
        Assert.AreEqual(expected.Match, actual.Match);
        Assert.AreEqual(expected.Secret, actual.Secret);
        Assert.AreEqual(expected.File, actual.File);
        Assert.AreEqual(expected.SymlinkFile, actual.SymlinkFile);
        Assert.AreEqual(expected.Commit, actual.Commit);
        Assert.AreEqual(expected.Entropy, actual.Entropy);
        Assert.AreEqual(expected.Author, actual.Author);
        Assert.AreEqual(expected.Email, actual.Email);
        Assert.AreEqual(expected.Date, actual.Date);
        Assert.AreEqual(expected.Message, actual.Message);
        CollectionAssert.AreEqual(expected.Tags.ToArray(), actual.Tags.ToArray());
        Assert.AreEqual(expected.Fingerprint, actual.Fingerprint);
        Assert.AreEqual(expected.Line, actual.Line);
        Assert.AreEqual(expected.Link, actual.Link);
        Assert.AreEqual(expected.SecretSha256, actual.SecretSha256);
        Assert.AreEqual(expected.MatchSha256, actual.MatchSha256);
        Assert.AreEqual(expected.ValidationState, actual.ValidationState);
        Assert.AreEqual(expected.BlobSha256, actual.BlobSha256);
        CollectionAssert.AreEqual(expected.DecodePath.ToArray(), actual.DecodePath.ToArray());
    }

    private static void AssertHasNoGroupOrOtherBits(UnixFileMode mode)
    {
        const UnixFileMode GroupOrOtherBits =
            UnixFileMode.GroupRead
            | UnixFileMode.GroupWrite
            | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherWrite
            | UnixFileMode.OtherExecute;
        Assert.AreEqual((UnixFileMode)0, mode & GroupOrOtherBits);
    }
}
