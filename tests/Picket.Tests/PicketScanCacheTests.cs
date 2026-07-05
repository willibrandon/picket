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
}
