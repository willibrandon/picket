using Picket.Sources;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketIgnore" />.
/// </summary>
[TestClass]
public sealed class PicketIgnoreTests
{
    /// <summary>
    /// Verifies that SHA-256 content-hash ignore entries are parsed.
    /// </summary>
    [TestMethod]
    public void FromLinesParsesSha256ContentHashes()
    {
        string secretContent = "token-12345";
        string ignoredHash = ComputeSha256(secretContent);
        PicketIgnore ignore = PicketIgnore.FromLines([
            "# comment",
            string.Empty,
            $"sha256:{ignoredHash.ToLowerInvariant()} # inline comment",
            "ignored.txt",
            "sha256:not-a-hash",
        ]);

        Assert.AreEqual(1, ignore.ContentHashCount);
        Assert.IsTrue(ignore.IsContentHashIgnored(Encoding.UTF8.GetBytes(secretContent)));
        Assert.IsFalse(ignore.IsContentHashIgnored(Encoding.UTF8.GetBytes("token-23456")));
    }

    /// <summary>
    /// Verifies that matched SHA-256 content-hash entries are excluded from stale-ignore audit results.
    /// </summary>
    [TestMethod]
    public void TryIgnoreContentHashRecordsMatchedHashesForAudit()
    {
        string matchedContent = "token-12345";
        string unmatchedContent = "token-23456";
        string matchedHash = ComputeSha256(matchedContent);
        string unmatchedHash = ComputeSha256(unmatchedContent);
        PicketIgnore ignore = PicketIgnore.FromLines([
            $"sha256:{matchedHash}",
            $"sha256:{unmatchedHash}",
        ]);

        Assert.IsTrue(ignore.TryIgnoreContentHash(Encoding.UTF8.GetBytes(matchedContent)));

        List<string> unmatchedEntries = ignore.GetUnmatchedContentHashEntries();

        Assert.HasCount(1, unmatchedEntries);
        Assert.Contains(unmatchedHash, unmatchedEntries[0]);
        Assert.DoesNotContain(matchedHash, unmatchedEntries[0]);
    }

    /// <summary>
    /// Verifies that precomputed SHA-256 identities participate in stale-ignore auditing.
    /// </summary>
    [TestMethod]
    public void TryIgnoreContentHashAcceptsPrecomputedHash()
    {
        string content = "token-12345";
        string hash = ComputeSha256(content);
        PicketIgnore ignore = PicketIgnore.FromLines([$"sha256:{hash}"]);

        bool ignored = ignore.TryIgnoreContentHash(hash.ToLowerInvariant());

        Assert.IsTrue(ignored);
        Assert.IsEmpty(ignore.GetUnmatchedContentHashEntries());
    }

    /// <summary>
    /// Verifies that parallel scans can record the same matched content hash safely.
    /// </summary>
    [TestMethod]
    public void TryIgnoreContentHashRecordsConcurrentMatches()
    {
        const int OperationCount = 256;
        string hash = ComputeSha256("token-12345");
        PicketIgnore ignore = PicketIgnore.FromLines([$"sha256:{hash}"]);
        var ignored = new bool[OperationCount];

        Parallel.For(0, OperationCount, operationIndex =>
        {
            ignored[operationIndex] = ignore.TryIgnoreContentHash(hash);
        });

        Assert.DoesNotContain(false, ignored);
        Assert.IsEmpty(ignore.GetUnmatchedContentHashEntries());
    }

    /// <summary>
    /// Verifies that precomputed ignore identities require a complete SHA-256 value.
    /// </summary>
    [TestMethod]
    public void TryIgnoreContentHashRejectsInvalidSha256()
    {
        Assert.ThrowsExactly<ArgumentException>(() => PicketIgnore.Empty.TryIgnoreContentHash("../unsafe"));
    }

    /// <summary>
    /// Verifies that root and explicit ignore files are loaded together.
    /// </summary>
    [TestMethod]
    public void LoadExistingReadsRootAndExplicitIgnoreFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        string rootContent = "token-12345";
        string explicitContent = "token-23456";
        string explicitIgnorePath = Path.Combine(root.Path, "extra.ignore");
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), $"sha256:{ComputeSha256(rootContent)}\n");
        File.WriteAllText(explicitIgnorePath, $"sha256:{ComputeSha256(explicitContent)}\n");

        PicketIgnore ignore = PicketIgnore.LoadExisting(root.Path, [explicitIgnorePath]);

        Assert.AreEqual(2, ignore.ContentHashCount);
        Assert.IsTrue(ignore.IsContentHashIgnored(Encoding.UTF8.GetBytes(rootContent)));
        Assert.IsTrue(ignore.IsContentHashIgnored(Encoding.UTF8.GetBytes(explicitContent)));
    }

    /// <summary>
    /// Verifies that loaded SHA-256 content-hash entries preserve their source location for audit output.
    /// </summary>
    [TestMethod]
    public void LoadExistingPreservesContentHashEntryLocations()
    {
        using TempDirectory root = TempDirectory.Create();
        string content = "token-12345";
        string ignorePath = Path.Combine(root.Path, ".picketignore");
        File.WriteAllText(ignorePath, $"sha256:{ComputeSha256(content)}\n");

        PicketIgnore ignore = PicketIgnore.LoadExisting([ignorePath]);

        List<string> unmatchedEntries = ignore.GetUnmatchedContentHashEntries();

        Assert.HasCount(1, unmatchedEntries);
        Assert.Contains($"{ignorePath}:1", unmatchedEntries[0]);
    }

    private static string ComputeSha256(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
}
