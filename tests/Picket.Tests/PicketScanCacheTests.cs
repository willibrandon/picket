using Picket.Engine;
using Picket.Rules;
using Picket.Store;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketScanCache" />.
/// </summary>
[TestClass]
public sealed class PicketScanCacheTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

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
    /// Verifies stable stream hashing without closing the caller-owned stream.
    /// </summary>
    [TestMethod]
    public void BlobHasherComputesStableStreamSha256()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        string hash = BlobHasher.ComputeSha256Hex(stream, TestContext.CancellationToken);

        Assert.AreEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
        Assert.AreEqual(stream.Length, stream.Position);
        Assert.IsTrue(stream.CanRead);
    }

    /// <summary>
    /// Verifies scan cache keys require path-safe SHA-256 fingerprints.
    /// </summary>
    [TestMethod]
    public void ScanCacheKeyRejectsUnsafeFingerprint()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new ScanCacheKey("../unsafe"));
    }

    /// <summary>
    /// Verifies that scanner matching behavior participates in scan-cache identities.
    /// </summary>
    [TestMethod]
    public void ScanCacheKeyIncludesMatchingBehaviorVersion()
    {
        string ruleSetFingerprint = new('a', 64);
        ScanCacheKey key = ScanCacheKey.Create(ruleSetFingerprint, maxDecodeDepth: 5, maxTargetBytes: null);
        string material = string.Concat(
            "picket.scan-cache-key.v4\nmatching-behavior:",
            SecretScanner.MatchingBehaviorVersion,
            "\nrandomness-model:",
            SecretRandomnessScorer.ModelVersion,
            "\nrules:",
            ruleSetFingerprint,
            "\ndecode:5\ntarget:none\nignore-gitleaks-allow:false\nstorage-mode:SecretHashOnly");

        Assert.AreEqual(BlobHasher.ComputeSha256Hex(material), key.Fingerprint);
    }

    /// <summary>
    /// Verifies offline validation model versions participate in scan-cache identities.
    /// </summary>
    [TestMethod]
    public void ScanCacheKeyIncludesValidationModelVersion()
    {
        string ruleSetFingerprint = new('a', 64);
        ScanCacheKey first = ScanCacheKey.Create(
            ruleSetFingerprint,
            maxDecodeDepth: 5,
            maxTargetBytes: null,
            validationModelVersion: "validation-v1");
        ScanCacheKey second = ScanCacheKey.Create(
            ruleSetFingerprint,
            maxDecodeDepth: 5,
            maxTargetBytes: null,
            validationModelVersion: "validation-v2");

        Assert.AreNotEqual(first.Fingerprint, second.Fingerprint);
    }

    /// <summary>
    /// Verifies scan-cache validation model versions cannot inject material delimiters.
    /// </summary>
    [TestMethod]
    public void ScanCacheKeyRejectsMultilineValidationModelVersion()
    {
        string ruleSetFingerprint = new('a', 64);

        Assert.ThrowsExactly<ArgumentException>(() => ScanCacheKey.Create(
            ruleSetFingerprint,
            maxDecodeDepth: 5,
            maxTargetBytes: null,
            validationModelVersion: "validation-v1\nrules:substitute"));
    }

    /// <summary>
    /// Verifies cached findings are rehydrated with the current source path.
    /// </summary>
    [TestMethod]
    public void TryReadReturnsCachedFindingsForSameBlobAndPath()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("prefix token-12345 suffix");
        Finding finding = CreateFinding("secret.txt");

        cache.Write(content, "secret.txt", [finding]);

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.AreEqual("secret.txt", cachedFindings[0].File);
        Assert.AreEqual("secret.txt:token:1", cachedFindings[0].Fingerprint);
        Assert.AreEqual(BlobHasher.ComputeSha256Hex(content), cachedFindings[0].BlobSha256);
        Assert.HasCount(1, cachedFindings[0].DecodePath);
        Assert.AreEqual("base64", cachedFindings[0].DecodePath[0]);
    }

    /// <summary>
    /// Verifies that precomputed blob identities address the same authenticated cache entries as content bytes.
    /// </summary>
    [TestMethod]
    public void TryReadReturnsCachedFindingsForPrecomputedBlobHash()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("prefix token-12345 suffix");
        string blobSha256 = BlobHasher.ComputeSha256Hex(content);

        cache.Write(blobSha256, "secret.txt", [CreateFinding("secret.txt")]);

        bool hit = cache.TryRead(blobSha256, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.AreEqual(blobSha256, cachedFindings[0].BlobSha256);
    }

    /// <summary>
    /// Verifies that precomputed cache identities reject values that cannot be safe entry names.
    /// </summary>
    [TestMethod]
    public void PrecomputedBlobHashRejectsInvalidSha256()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);

        Assert.ThrowsExactly<ArgumentException>(() => cache.TryRead("../unsafe", "secret.txt", string.Empty, out _));
        Assert.ThrowsExactly<ArgumentException>(() => cache.Write("../unsafe", "secret.txt", [CreateFinding("secret.txt")]));
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
        Assert.Contains("storageMode\tSecretHashOnly", entry);
        Assert.Contains("findingCount\t1", entry);
        Assert.Contains("mac\t", entry);
        Assert.AreEqual(root.Path, stats.RootPath);
        Assert.AreEqual(1, stats.EntryCount);
        Assert.AreEqual(1, stats.CurrentKeyEntryCount);
        Assert.AreNotEqual(0L, stats.TotalBytes);
    }

    /// <summary>
    /// Verifies cache directories and entry files are owner-only on Unix-like systems.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void WriteCreatesOwnerOnlyCacheFilesOnUnix()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(root.Path));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(Path.Combine(root.Path, "entries")));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(Path.Combine(root.Path, "locks")));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(GetSingleEntryPath(root.Path)));
    }

    /// <summary>
    /// Verifies cache directories, lock files, and entry files are owner-only on Windows.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void WriteCreatesOwnerOnlyCacheFilesOnWindows()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        WindowsAccessControlAssert.AllowsOnlyCurrentUser(root.Path);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(Path.Combine(root.Path, "entries"));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(Path.Combine(root.Path, "locks"));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(GetSingleEntryPath(root.Path));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(GetSingleLockPath(root.Path));
    }

    /// <summary>
    /// Verifies entries written before cache authentication was added are treated as misses.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsLegacyEntryWithoutAuthentication()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.Raw);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        string blobHash = BlobHasher.ComputeSha256Hex(content);
        string pathHash = BlobHasher.ComputeSha256Hex("secret.txt");
        string entryDirectory = Path.Combine(root.Path, "entries", blobHash[..2]);
        Directory.CreateDirectory(entryDirectory);
        File.WriteAllText(
            Path.Combine(entryDirectory, $"{blobHash}-{pathHash}-{cache.Key.Fingerprint}.cache"),
            CreateLegacyEntry(blobHash, cache.Key.Fingerprint));

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies secret-hash-only cache keys reject legacy entries that lack storage metadata.
    /// </summary>
    [TestMethod]
    public void TryReadSecretHashOnlyRejectsLegacyEntryWithoutStorageMode()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        string blobHash = BlobHasher.ComputeSha256Hex(content);
        string pathHash = BlobHasher.ComputeSha256Hex("secret.txt");
        string entryDirectory = Path.Combine(root.Path, "entries", blobHash[..2]);
        Directory.CreateDirectory(entryDirectory);
        File.WriteAllText(
            Path.Combine(entryDirectory, $"{blobHash}-{pathHash}-{cache.Key.Fingerprint}.cache"),
            CreateLegacyEntry(blobHash, cache.Key.Fingerprint));

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies cache entries from previous schemas are treated as misses.
    /// </summary>
    [TestMethod]
    [DataRow("picket.scan-cache.v3")]
    [DataRow("picket.scan-cache.v4")]
    public void TryReadRejectsPreviousSchemaEntry(string schema)
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        cache.Write(content, "secret.txt", [CreateFinding("secret.txt", includeRandomness: true)]);
        string entryPath = GetSingleEntryPath(root.Path);
        string entry = File.ReadAllText(entryPath).Replace(
            "picket.scan-cache.v5",
            schema,
            StringComparison.Ordinal);
        File.WriteAllText(entryPath, entry);

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
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
    /// Verifies secret-hash-only cache entries do not persist raw finding evidence.
    /// </summary>
    [TestMethod]
    public void TryReadSecretHashOnlyEntryReturnsHashesWithoutRawEvidence()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("prefix token-12345 suffix");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        string entryText = File.ReadAllText(GetSingleEntryPath(root.Path));
        string expectedHash = BlobHasher.ComputeSha256Hex("token-12345");
        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.IsEmpty(cachedFindings[0].Match);
        Assert.IsEmpty(cachedFindings[0].Secret);
        Assert.IsEmpty(cachedFindings[0].Line);
        Assert.AreEqual(expectedHash, cachedFindings[0].SecretSha256);
        Assert.AreEqual(expectedHash, cachedFindings[0].MatchSha256);
        Assert.Contains("storageMode\tSecretHashOnly", entryText);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("token-12345")), entryText);
        Assert.DoesNotContain(expectedHash, entryText);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(expectedHash)), entryText);
    }

    /// <summary>
    /// Verifies secret-hash-only cache entries preserve non-secret randomness assessments.
    /// </summary>
    [TestMethod]
    public void TryReadSecretHashOnlyEntryReturnsRandomnessAssessment()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("prefix token-12345 suffix");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt", includeRandomness: true)]);

        string entryText = File.ReadAllText(GetSingleEntryPath(root.Path));
        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        SecretRandomnessAssessment assessment = cachedFindings[0].Randomness
            ?? throw new InvalidOperationException("Cached finding did not preserve randomness metadata.");
        Assert.AreEqual(SecretRandomnessScorer.ModelVersion, assessment.Model);
        Assert.AreEqual(SecretRandomnessScorer.Assess("token-12345").Score, assessment.Score);
        Assert.AreEqual("likely-structured", assessment.Classification);
        Assert.AreEqual("alphanumeric", assessment.Features.Alphabet);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(SecretRandomnessScorer.ModelVersion)), entryText);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("alphanumeric")), entryText);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("likely-structured")), entryText);
    }

    /// <summary>
    /// Verifies cache reads reject entries whose storage metadata does not match the active key.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsMismatchedStorageModeMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        string entryPath = GetSingleEntryPath(root.Path);
        string entryText = File.ReadAllText(entryPath).Replace(
            "storageMode\tSecretHashOnly",
            "storageMode\tRaw",
            StringComparison.Ordinal);
        File.WriteAllText(entryPath, entryText);

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies cache reads reject entries edited after they were written.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsTamperedEntry()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        string entryPath = GetSingleEntryPath(root.Path);
        string entryText = File.ReadAllText(entryPath)
            .Replace("findingCount\t1", "findingCount\t0", StringComparison.Ordinal)
            .Replace("finding\t", "tampered\t", StringComparison.Ordinal);
        File.WriteAllText(entryPath, entryText);

        bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies authenticated cache entries cannot be moved to another logical address.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsEntryRelocatedToDifferentAddress()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "source.txt", [CreateFinding("source.txt")]);
        string sourceEntryPath = GetSingleEntryPath(root.Path);
        cache.Write(content, "target.txt", [CreateFinding("target.txt")]);
        string[] entryPaths = Directory.GetFiles(Path.Combine(root.Path, "entries"), "*.cache", SearchOption.AllDirectories);
        Assert.HasCount(2, entryPaths);
        string targetEntryPath = entryPaths[0].Equals(sourceEntryPath, StringComparison.Ordinal)
            ? entryPaths[1]
            : entryPaths[0];

        File.Delete(targetEntryPath);
        File.Copy(sourceEntryPath, targetEntryPath);

        bool hit = cache.TryRead(content, "target.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies cache writes are non-fatal when another process holds the entry lock.
    /// </summary>
    [TestMethod]
    public void WriteTreatsLockContentionAsNonFatal()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        using FileStream _ = new(GetSingleLockPath(root.Path), FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
    }

    /// <summary>
    /// Verifies cache statistics skip entries whose length cannot be read.
    /// </summary>
    [TestMethod]
    public void TryGetFileLengthReturnsFalseForDeletedEntry()
    {
        MethodInfo method = typeof(PicketScanCache).GetMethod(
            "TryGetFileLength",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Expected scan cache to expose a length probe.");
        object?[] arguments = [Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), 0L];

        bool success = method.Invoke(null, arguments) as bool?
            ?? throw new InvalidOperationException("Expected scan cache length probe to return a Boolean.");

        Assert.IsFalse(success);
        Assert.AreEqual(0L, arguments[1]);
    }

    /// <summary>
    /// Verifies content-addressed cache entries are reused across logical paths.
    /// </summary>
    [TestMethod]
    public void TryReadRehydratesContentAddressedFindingsForDifferentPath()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, addressMode: ScanCacheAddressMode.Content);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "first.txt", [CreateFinding("first.txt")]);

        bool hit = cache.TryRead(content, "second.txt", "link.txt", out List<Finding>? cachedFindings);

        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.AreEqual("second.txt", cachedFindings[0].File);
        Assert.AreEqual("link.txt", cachedFindings[0].SymlinkFile);
        Assert.AreEqual("second.txt:token:1", cachedFindings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies extension-addressed cache entries reuse same-extension paths only.
    /// </summary>
    [TestMethod]
    public void TryReadReusesFileExtensionAddressedFindingsForSameExtension()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, addressMode: ScanCacheAddressMode.FileExtension);
        byte[] content = Encoding.UTF8.GetBytes("token-12345");

        cache.Write(content, "first.cs", [CreateFinding("first.cs")]);

        bool sameExtensionHit = cache.TryRead(content, "second.cs", string.Empty, out List<Finding>? sameExtensionFindings);
        bool differentExtensionHit = cache.TryRead(content, "second.txt", string.Empty, out List<Finding>? differentExtensionFindings);

        Assert.IsTrue(sameExtensionHit);
        Assert.IsNotNull(sameExtensionFindings);
        Assert.HasCount(1, sameExtensionFindings);
        Assert.AreEqual("second.cs", sameExtensionFindings[0].File);
        Assert.IsFalse(differentExtensionHit);
        Assert.IsNull(differentExtensionFindings);
    }

    /// <summary>
    /// Verifies compiled rule sets report whether matching can depend on source paths.
    /// </summary>
    [TestMethod]
    public void CompiledRuleSetReportsPathSensitiveMatching()
    {
        var contentOnlyRules = new RuleSet([SecretRule.Create("token", string.Empty, "token-[0-9]+")]);
        var pathScopedRules = new RuleSet([SecretRule.Create("token", string.Empty, "token-[0-9]+", pathPattern: "secrets/")]);
        var pathAllowlistRules = new RuleSet(
            [SecretRule.Create("token", string.Empty, "token-[0-9]+")],
            allowlists: [SecretAllowlist.Create(pathPatterns: ["ignored/"])]);

        Assert.IsFalse(CompiledRuleSet.Compile(contentOnlyRules).UsesPathSensitiveMatching);
        Assert.IsTrue(CompiledRuleSet.Compile(pathScopedRules).UsesPathSensitiveMatching);
        Assert.IsTrue(CompiledRuleSet.Compile(pathAllowlistRules).UsesPathSensitiveMatching);
    }

    /// <summary>
    /// Verifies native rule metadata participates in the compiled rule-set fingerprint.
    /// </summary>
    [TestMethod]
    public void CompiledRuleSetFingerprintIncludesNativeRuleMetadata()
    {
        string baseline = CreateRuleSetFingerprint(SecretRule.Create("token", string.Empty, "token-[0-9]+"));
        string validation = CreateRuleSetFingerprint(SecretRule.Create(
            "token",
            string.Empty,
            "token-[0-9]+",
            validation: ["offline:example"]));
        string revocation = CreateRuleSetFingerprint(SecretRule.Create(
            "token",
            string.Empty,
            "token-[0-9]+",
            revocation: ["revocation:example"]));
        string deprecated = CreateRuleSetFingerprint(SecretRule.Create(
            "token",
            string.Empty,
            "token-[0-9]+",
            deprecated: true));
        string randomnessThreshold = CreateRuleSetFingerprint(SecretRule.Create(
            "token",
            string.Empty,
            "token-[0-9]+",
            randomnessThreshold: 0.8));
        string detector = CreateRuleSetFingerprint(SecretRule.Create(
            "token",
            string.Empty,
            "token-[0-9]+",
            detector: PicketBuiltInDetectorNames.CodexCredentials));

        Assert.AreNotEqual(baseline, validation);
        Assert.AreNotEqual(baseline, revocation);
        Assert.AreNotEqual(baseline, deprecated);
        Assert.AreNotEqual(baseline, randomnessThreshold);
        Assert.AreNotEqual(baseline, detector);
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
    /// Verifies concurrent cache reads and writes preserve authenticated complete entries.
    /// </summary>
    [TestMethod]
    [Timeout(15000, CooperativeCancellation = true)]
    public async Task ConcurrentReadsAndWritesNeverReturnPartialEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);
        byte[] content = Encoding.UTF8.GetBytes("prefix token-12345 suffix");
        Finding finding = CreateFinding("secret.txt", includeRandomness: true);
        Finding[] findings = [finding];
        string expectedSecretSha256 = BlobHasher.ComputeSha256Hex(finding.Secret);
        cache.Write(content, "secret.txt", findings);
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var tasks = new Task[16];
        for (int taskIndex = 0; taskIndex < tasks.Length; taskIndex++)
        {
            tasks[taskIndex] = Task.Run(() =>
            {
                for (int iteration = 0; iteration < 25; iteration++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    cache.Write(content, "secret.txt", findings);
                    bool hit = cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

                    if (hit)
                    {
                        Assert.IsNotNull(cachedFindings);
                        Assert.HasCount(1, cachedFindings);
                        Assert.AreEqual(expectedSecretSha256, cachedFindings[0].SecretSha256);
                    }
                    else
                    {
                        Assert.IsNull(cachedFindings);
                    }
                }
            }, cancellationToken);
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);

        Assert.IsTrue(cache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? finalFindings));
        Assert.IsNotNull(finalFindings);
        Assert.HasCount(1, finalFindings);
        Assert.AreEqual(expectedSecretSha256, finalFindings[0].SecretSha256);
    }

    /// <summary>
    /// Verifies storage modes participate in scan-cache keys.
    /// </summary>
    [TestMethod]
    public void TryReadMissesForDifferentStorageMode()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache rawCache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.Raw);
        PicketScanCache hashOnlyCache = CreateCache(root.Path, storageMode: ScanCacheStorageMode.SecretHashOnly);

        rawCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        bool hit = hashOnlyCache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.IsFalse(hit);
        Assert.IsNull(cachedFindings);
    }

    /// <summary>
    /// Verifies inline allow behavior participates in scan-cache keys.
    /// </summary>
    [TestMethod]
    public void TryReadMissesForDifferentGitleaksAllowBehavior()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345 # gitleaks:allow");
        PicketScanCache honoringAllowCache = CreateCache(root.Path, ignoreGitleaksAllow: false);
        PicketScanCache ignoringAllowCache = CreateCache(root.Path, ignoreGitleaksAllow: true);

        honoringAllowCache.Write(content, "secret.txt", []);

        bool hit = ignoringAllowCache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

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

    /// <summary>
    /// Verifies cache export writes only entries for the active scanner key.
    /// </summary>
    [TestMethod]
    public void ExportWritesOnlyCurrentScannerKeyEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache firstCache = CreateCache(root.Path, "token-[0-9]+");
        PicketScanCache secondCache = CreateCache(root.Path, "token-[A-Z]+");
        string archivePath = Path.Combine(root.Path, "cache.zip");

        firstCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        secondCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);

        int exported = firstCache.Export(archivePath);

        Assert.AreEqual(1, exported);
        using var archive = ZipFile.OpenRead(archivePath);
        Assert.HasCount(1, archive.Entries);
        Assert.Contains(firstCache.Key.Fingerprint, archive.Entries[0].FullName);
        Assert.DoesNotContain(secondCache.Key.Fingerprint, archive.Entries[0].FullName);
    }

    /// <summary>
    /// Verifies cache export skips corrupt entries because normal scans treat them as misses.
    /// </summary>
    [TestMethod]
    public void ExportSkipsCorruptEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache cache = CreateCache(root.Path);
        string archivePath = Path.Combine(root.Path, "cache.zip");

        cache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        File.WriteAllText(GetSingleEntryPath(root.Path), "not a cache entry");

        int exported = cache.Export(archivePath);

        Assert.AreEqual(0, exported);
        using var archive = ZipFile.OpenRead(archivePath);
        Assert.IsEmpty(archive.Entries);
    }

    /// <summary>
    /// Verifies cache import restores usable current-key entries.
    /// </summary>
    [TestMethod]
    public void ImportRestoresExportedEntries()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string archivePath = Path.Combine(sourceRoot.Path, "cache.zip");

        sourceCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        int exported = sourceCache.Export(archivePath);
        int imported = destinationCache.Import(archivePath);
        bool hit = destinationCache.TryRead(content, "secret.txt", string.Empty, out List<Finding>? cachedFindings);

        Assert.AreEqual(1, exported);
        Assert.AreEqual(1, imported);
        Assert.IsTrue(hit);
        Assert.IsNotNull(cachedFindings);
        Assert.HasCount(1, cachedFindings);
        Assert.IsEmpty(cachedFindings[0].Secret);
        Assert.AreEqual(BlobHasher.ComputeSha256Hex("token-12345"), cachedFindings[0].SecretSha256);
    }

    /// <summary>
    /// Verifies cache import does not let archive-supplied timestamps make new entries immediately pruneable.
    /// </summary>
    [TestMethod]
    public void ImportDoesNotTrustArchiveEntryTimestampsForPruning()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string archivePath = Path.Combine(sourceRoot.Path, "cache.zip");

        sourceCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        File.SetLastWriteTimeUtc(GetSingleEntryPath(sourceRoot.Path), DateTime.UtcNow - TimeSpan.FromDays(30));
        Assert.AreEqual(1, sourceCache.Export(archivePath));

        int imported = destinationCache.Import(archivePath);
        int pruned = destinationCache.PruneOlderThan(TimeSpan.FromDays(1));

        Assert.AreEqual(1, imported);
        Assert.AreEqual(0, pruned);
        Assert.AreEqual(1, destinationCache.GetStats().EntryCount);
        Assert.IsTrue(destinationCache.TryRead(content, "secret.txt", string.Empty, out _));
    }

    /// <summary>
    /// Verifies cache import skips entries whose lock is held by another writer.
    /// </summary>
    [TestMethod]
    public void ImportSkipsEntryWhenLockHeld()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string archivePath = Path.Combine(sourceRoot.Path, "cache.zip");

        sourceCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        Assert.AreEqual(1, sourceCache.Export(archivePath));
        string lockPath = GetSingleArchiveEntryLockPath(destinationRoot.Path, archivePath);
        Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
        using (FileStream _ = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            int importedWhileLocked = destinationCache.Import(archivePath);

            Assert.AreEqual(0, importedWhileLocked);
            Assert.IsEmpty(Directory.GetFiles(Path.Combine(destinationRoot.Path, "entries"), "*.cache", SearchOption.AllDirectories));
        }

        int importedAfterLockReleased = destinationCache.Import(archivePath);

        Assert.AreEqual(1, importedAfterLockReleased);
        Assert.IsTrue(destinationCache.TryRead(content, "secret.txt", string.Empty, out _));
    }

    /// <summary>
    /// Verifies cache import does not keep staged entries when a later current-key entry is invalid.
    /// </summary>
    [TestMethod]
    public void ImportRejectsInvalidCurrentKeyEntryWithoutPartialImport()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string exportedArchivePath = Path.Combine(sourceRoot.Path, "cache.zip");
        string invalidArchivePath = Path.Combine(sourceRoot.Path, "invalid-cache.zip");

        sourceCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        Assert.AreEqual(1, sourceCache.Export(exportedArchivePath));
        string entryName;
        byte[] entryBytes;
        using (ZipArchive exportedArchive = ZipFile.OpenRead(exportedArchivePath))
        {
            Assert.HasCount(1, exportedArchive.Entries);
            ZipArchiveEntry exportedEntry = exportedArchive.Entries[0];
            entryName = exportedEntry.FullName;
            using Stream input = exportedEntry.Open();
            using var output = new MemoryStream();
            input.CopyTo(output);
            entryBytes = output.ToArray();
        }

        using (FileStream archiveStream = File.Create(invalidArchivePath))
        using (var archive = new ZipArchive(archiveStream, ZipArchiveMode.Create))
        {
            WriteZipEntryBytes(archive, entryName, entryBytes);
            WriteZipEntryBytes(archive, entryName, Encoding.UTF8.GetBytes("not a valid cache entry"));
        }

        FormatException exception = Assert.ThrowsExactly<FormatException>(() => destinationCache.Import(invalidArchivePath));

        Assert.Contains("Invalid cache archive entry content", exception.Message);
        Assert.IsEmpty(Directory.GetFiles(Path.Combine(destinationRoot.Path, "entries"), "*.cache", SearchOption.AllDirectories));
    }

    /// <summary>
    /// Verifies cache import rejects archive paths that could escape the cache root.
    /// </summary>
    [TestMethod]
    public void ImportRejectsPathTraversalArchiveEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        PicketScanCache cache = CreateCache(root.Path);
        string archivePath = Path.Combine(root.Path, "cache.zip");
        WriteZipEntry(archivePath, "../evil.cache", "not a cache entry");

        Assert.ThrowsExactly<FormatException>(() => cache.Import(archivePath));
        Assert.IsFalse(File.Exists(Path.Combine(root.Path, "evil.cache")));
    }

    /// <summary>
    /// Verifies cache import rejects entries that exceed the decompressed entry budget.
    /// </summary>
    [TestMethod]
    public void ImportRejectsEntriesAboveConfiguredDecompressedSize()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string exportedArchivePath = Path.Combine(sourceRoot.Path, "cache.zip");
        string oversizedArchivePath = Path.Combine(sourceRoot.Path, "oversized-cache.zip");

        sourceCache.Write(content, "secret.txt", [CreateFinding("secret.txt")]);
        Assert.AreEqual(1, sourceCache.Export(exportedArchivePath));
        using (ZipArchive exportedArchive = ZipFile.OpenRead(exportedArchivePath))
        {
            Assert.HasCount(1, exportedArchive.Entries);
            WriteZipEntry(oversizedArchivePath, exportedArchive.Entries[0].FullName, new string('x', 33));
        }

        FormatException exception = Assert.ThrowsExactly<FormatException>(() => destinationCache.Import(oversizedArchivePath, maxEntryBytes: 32));

        Assert.Contains("exceeds maximum decompressed size", exception.Message);
        Assert.IsEmpty(Directory.GetFiles(Path.Combine(destinationRoot.Path, "entries"), "*.cache", SearchOption.AllDirectories));
    }

    /// <summary>
    /// Verifies cache import rejects archives that exceed the entry-count budget.
    /// </summary>
    [TestMethod]
    public void ImportRejectsArchivesAboveConfiguredEntryCount()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string archivePath = Path.Combine(sourceRoot.Path, "cache.zip");

        sourceCache.Write(content, "first.txt", [CreateFinding("first.txt")]);
        sourceCache.Write(content, "second.txt", [CreateFinding("second.txt")]);
        Assert.AreEqual(2, sourceCache.Export(archivePath));

        FormatException exception = Assert.ThrowsExactly<FormatException>(
            () => destinationCache.Import(archivePath, maxEntryBytes: 100_000_000, maxEntries: 1, maxTotalBytes: 1_000_000_000));

        Assert.Contains("maximum entry count", exception.Message);
    }

    /// <summary>
    /// Verifies cache import rejects archives that exceed the aggregate decompressed-byte budget.
    /// </summary>
    [TestMethod]
    public void ImportRejectsArchivesAboveConfiguredTotalDecompressedSize()
    {
        using TempDirectory sourceRoot = TempDirectory.Create();
        using TempDirectory destinationRoot = TempDirectory.Create();
        byte[] content = Encoding.UTF8.GetBytes("token-12345");
        PicketScanCache sourceCache = CreateCache(sourceRoot.Path);
        PicketScanCache destinationCache = CreateCache(destinationRoot.Path);
        string archivePath = Path.Combine(sourceRoot.Path, "cache.zip");

        sourceCache.Write(content, "first.txt", [CreateFinding("first.txt")]);
        sourceCache.Write(content, "second.txt", [CreateFinding("second.txt")]);
        Assert.AreEqual(2, sourceCache.Export(archivePath));
        long largestEntryBytes = GetLargestArchiveEntryLength(archivePath);

        FormatException exception = Assert.ThrowsExactly<FormatException>(
            () => destinationCache.Import(archivePath, maxEntryBytes: 100_000_000, maxEntries: 100, maxTotalBytes: largestEntryBytes));

        Assert.Contains("maximum decompressed size", exception.Message);
    }

    private static PicketScanCache CreateCache(
        string root,
        string pattern = "token-[0-9]+",
        bool ignoreGitleaksAllow = false,
        ScanCacheAddressMode addressMode = ScanCacheAddressMode.Path,
        ScanCacheStorageMode storageMode = ScanCacheStorageMode.SecretHashOnly)
    {
        var ruleSet = new RuleSet([SecretRule.Create("token", string.Empty, pattern)]);
        CompiledRuleSet compiledRuleSet = CompiledRuleSet.Compile(ruleSet);
        return PicketScanCache.Open(root, ScanCacheKey.Create(compiledRuleSet.Fingerprint, maxDecodeDepth: 5, maxTargetBytes: null, ignoreGitleaksAllow, addressMode, storageMode));
    }

    private static string CreateRuleSetFingerprint(SecretRule rule)
    {
        return CompiledRuleSet.Compile(new RuleSet([rule])).Fingerprint;
    }

    private static Finding CreateFinding(string file, bool includeRandomness = false)
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
            "token-12345",
            decodePath: ["base64"],
            randomness: includeRandomness ? SecretRandomnessScorer.Assess("token-12345") : null,
            positionKind: FindingPositionKind.UnicodeCodePointsExclusive);
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

    private static string GetSingleArchiveEntryLockPath(string cacheRoot, string archivePath)
    {
        using ZipArchive archive = ZipFile.OpenRead(archivePath);
        Assert.HasCount(1, archive.Entries);
        string fileName = Path.GetFileName(archive.Entries[0].FullName);
        string[] parts = fileName.Split('-');
        Assert.HasCount(3, parts);
        return Path.Combine(cacheRoot, "locks", string.Concat(parts[0], "-", parts[1], ".lock"));
    }

    private static long GetLargestArchiveEntryLength(string archivePath)
    {
        long largestEntryLength = 0;
        using ZipArchive archive = ZipFile.OpenRead(archivePath);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            largestEntryLength = Math.Max(largestEntryLength, entry.Length);
        }

        return largestEntryLength;
    }

    private static string GetSingleLockPath(string root)
    {
        string[] entries = Directory.GetFiles(Path.Combine(root, "locks"), "*.lock", SearchOption.AllDirectories);
        Assert.HasCount(1, entries);
        return entries[0];
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

    private static void WriteZipEntry(string archivePath, string entryName, string content)
    {
        using FileStream archiveStream = File.Create(archivePath);
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Create);
        ZipArchiveEntry entry = archive.CreateEntry(entryName);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private static void WriteZipEntryBytes(ZipArchive archive, string entryName, byte[] content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(entryName);
        using Stream output = entry.Open();
        output.Write(content);
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
