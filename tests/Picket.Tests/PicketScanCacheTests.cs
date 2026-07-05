using System.Text;
using Picket.Engine;
using Picket.Rules;
using Picket.Store;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketScanCache" />.
/// </summary>
[TestClass]
public sealed class PicketScanCacheTests
{
    /// <summary>
    /// Verifies stable SHA-256 content identities.
    /// </summary>
    [TestMethod]
    public void BlobHasherComputesStableSha256()
    {
        string hash = BlobHasher.ComputeSha256Hex("abc");

        Assert.AreEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
    }

    /// <summary>
    /// Verifies cached findings are rehydrated with the current source path.
    /// </summary>
    [TestMethod]
    public void TryReadReturnsCachedFindingsForSameBlobAndPath()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        Finding finding = CreateFinding("secret.txt");

        cache.Write(content, "secret.txt", [finding]);

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.AreEqual("secret.txt", cachedFindings[0].File);
        Assert.AreEqual("secret.txt:token:1", cachedFindings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies cache entries include metadata and cache statistics report active entries.
    /// </summary>
    [TestMethod]
    public void WriteAddsMetadataAndStats()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        string entry = File.ReadAllText(GetSingleEntryPath(root.Path));
        PicketScanCacheStats stats = cache.GetStats();
        Assert.Contains("createdUnixTimeSeconds\t", entry);
        Assert.Contains("findingCount\t1", entry);
        Assert.AreEqual(root.Path, stats.RootPath);
        Assert.AreEqual(1, stats.EntryCount);
        Assert.AreEqual(1, stats.CurrentKeyEntryCount);
        Assert.AreNotEqual(0L, stats.TotalBytes);
    }

    /// <summary>
    /// Verifies entries written before cache metadata was added remain readable.
    /// </summary>
    [TestMethod]
    public void TryReadAcceptsLegacyEntryWithoutMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        string blobHash = BlobHasher.ComputeSha256Hex(content);
        string pathHash = BlobHasher.ComputeSha256Hex("secret.txt");
        string entryDirectory = Path.Combine(root.Path, "entries", blobHash[..2]);
        Directory.CreateDirectory(entryDirectory);
        File.WriteAllText(
            Path.Combine(entryDirectory, $"{blobHash}-{pathHash}-{cache.Key.Fingerprint}.cache"),
            CreateLegacyEntry(blobHash, cache.Key.Fingerprint));

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.AreEqual("token-12345", cachedFindings[0].Secret);
    }

    /// <summary>
    /// Verifies path-sensitive cache keys do not reuse findings across logical paths.
    /// </summary>
    [TestMethod]
    public void TryReadMissesForDifferentPath()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        bool hit = cache.TryRead(content, "other.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies rule-set fingerprints invalidate old cache entries.
    /// </summary>
    [TestMethod]
    public void TryReadMissesForDifferentRuleSetFingerprint()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache firstCache = CreateCache(root.Path, "token-[0-9]+");
        PicketScanCache secondCache = CreateCache(root.Path, "token-[A-Z]+");

        firstCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        bool hit = secondCache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies old scanner configuration entries can be pruned.
    /// </summary>
    [TestMethod]
    public void PruneOtherKeysDeletesInactiveEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache firstCache = CreateCache(root.Path, "token-[0-9]+");
        PicketScanCache secondCache = CreateCache(root.Path, "token-[A-Z]+");

        firstCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        PicketScanCacheStats before = secondCache.GetStats();
        int deleted = secondCache.PruneOtherKeys();
        PicketScanCacheStats after = secondCache.GetStats();
        Assert.AreEqual(1, before.EntryCount);
        Assert.AreEqual(0, before.CurrentKeyEntryCount);
        Assert.AreEqual(1, deleted);
        Assert.AreEqual(0, after.EntryCount);
    }

    /// <summary>
    /// Verifies aged cache entries can be pruned.
    /// </summary>
    [TestMethod]
    public void PruneOlderThanDeletesExpiredEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        File.SetLastWriteTimeUtc(GetSingleEntryPath(root.Path), DateTime.UtcNow - TimeSpan.FromDays(2));

        int deleted = cache.PruneOlderThan(TimeSpan.FromDays(1));

        Assert.AreEqual(1, deleted);
        Assert.AreEqual(0, cache.GetStats().EntryCount);
    }

    private static PicketScanCache CreateCache(string root, string pattern = "token-[0-9]+")
    {
        var ruleSet = new RuleSet([SecretRule.Create("token", string.Empty, pattern)]);
        CompiledRuleSet compiledRuleSet = CompiledRuleSet.Compile(ruleSet);
        return PicketScanCache.Open(root, ScanCacheKey.Create(compiledRuleSet.Fingerprint, maxDecodeDepth: 5, maxTargetBytes: null));
    }

    private static Finding CreateFinding(string file)
    {
        return new Finding(
            "token",
            string.Empty,
            1,
            1,
            1,
            12,
            "token-12345",
            "token-12345",
            file,
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            $"{file}:token:1",
            "token-12345");
    }

    private static string CreateLegacyEntry(string blobHash, string keyFingerprint)
    {
        var builder = new StringBuilder();
        builder.Append("picket.scan-cache.v1\n");
        builder.Append("key\t");
        builder.Append(Encode(keyFingerprint));
        builder.Append('\n');
        builder.Append("blob\t");
        builder.Append(Encode(blobHash));
        builder.Append('\n');
        builder.Append("finding");
        Append(builder, Encode("token"));
        Append(builder, Encode(string.Empty));
        Append(builder, "1");
        Append(builder, "1");
        Append(builder, "1");
        Append(builder, "12");
        Append(builder, Encode("token-12345"));
        Append(builder, Encode("token-12345"));
        Append(builder, Encode("token-12345"));
        Append(builder, "0");
        Append(builder, string.Empty);
        Append(builder, Encode(string.Empty));
        Append(builder, Encode(string.Empty));
        Append(builder, Encode(string.Empty));
        builder.Append('\n');
        return builder.ToString();
    }

    private static string GetSingleEntryPath(string root)
    {
        string[] entries = Directory.GetFiles(Path.Combine(root, "entries"), "*.cache", SearchOption.AllDirectories);
        Assert.HasCount(1, entries);
        return entries[0];
    }

    private static void Append(StringBuilder builder, string value)
    {
        builder.Append('\t');
        builder.Append(value);
    }

    private static string Encode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }
}
