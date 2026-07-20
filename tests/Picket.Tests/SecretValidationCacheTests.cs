using Picket.Engine;
using Picket.Verify;
using System.Runtime.Versioning;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="SecretValidationCache" />.
/// </summary>
[TestClass]
public sealed class SecretValidationCacheTests
{
    /// <summary>
    /// Verifies that live validation cache entries round-trip without storing raw secrets.
    /// </summary>
    [TestMethod]
    public void WriteStoresResultWithoutRawSecretMaterial()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        Finding finding = CreateFinding();
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            finding,
            new Uri("https://api.github.com/user"));

        cache.Write(
            key,
            new SecretValidationResult(
                SecretValidationState.Active,
                "provider accepted token",
                "octocat",
                ["repo", "gist"],
                ["github:user"],
                ["githubLogin=octocat"]),
            DateTimeOffset.UtcNow.AddMinutes(5));

        bool found = cache.TryRead(key, DateTimeOffset.UtcNow, out SecretValidationResult? result);
        string storedText = ReadCacheText(temp.Path);

        Assert.IsTrue(found);
        Assert.IsNotNull(result);
        Assert.AreEqual(SecretValidationState.Active, result.State);
        Assert.AreEqual("octocat", result.Identity);
        Assert.Contains("repo", result.Scopes);
        Assert.Contains("gist", result.Scopes);
        Assert.Contains("github:user", result.ReachableResources);
        Assert.Contains("githubLogin=octocat", result.Evidence);
        Assert.DoesNotContain(finding.Secret, storedText);
        Assert.Contains("picket.validation-cache.v2", storedText);
        Assert.Contains("mac\t", storedText);
    }

    /// <summary>
    /// Verifies that validation cache reads reject entries whose authenticated body was changed.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsTamperedEntry()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));
        cache.Write(key, new SecretValidationResult(SecretValidationState.Active), DateTimeOffset.UtcNow.AddMinutes(5));
        string entryPath = GetSingleEntryPath(temp.Path);
        string tampered = File.ReadAllText(entryPath).Replace("state\tactive", "state\tinvalid", StringComparison.Ordinal);
        File.WriteAllText(entryPath, tampered, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        bool found = cache.TryRead(key, DateTimeOffset.UtcNow, out SecretValidationResult? result);

        Assert.IsFalse(found);
        Assert.IsNull(result);
    }

    /// <summary>
    /// Verifies validation cache entries written without authentication are treated as misses.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsLegacyEntryWithoutAuthentication()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));
        cache.Write(key, new SecretValidationResult(SecretValidationState.Active), DateTimeOffset.UtcNow.AddMinutes(5));
        string entryPath = GetSingleEntryPath(temp.Path);
        string authenticated = File.ReadAllText(entryPath);
        int macLineStart = authenticated.LastIndexOf("\nmac\t", StringComparison.Ordinal);
        File.WriteAllText(entryPath, authenticated[..(macLineStart + 1)], new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        bool found = cache.TryRead(key, DateTimeOffset.UtcNow, out SecretValidationResult? result);

        Assert.IsFalse(found);
        Assert.IsNull(result);
    }

    /// <summary>
    /// Verifies validation cache directories, lock files, and entry files are owner-only on Unix-like systems.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void WriteCreatesOwnerOnlyValidationCacheFilesOnUnix()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));

        cache.Write(key, new SecretValidationResult(SecretValidationState.Active), DateTimeOffset.UtcNow.AddMinutes(5));

        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(temp.Path));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(Path.Combine(temp.Path, "entries")));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(Path.Combine(temp.Path, "locks")));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(GetSingleEntryPath(temp.Path)));
        AssertHasNoGroupOrOtherBits(File.GetUnixFileMode(GetSingleLockPath(temp.Path)));
    }

    /// <summary>
    /// Verifies validation cache directories, lock files, and entry files are owner-only on Windows.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void WriteCreatesOwnerOnlyValidationCacheFilesOnWindows()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));

        cache.Write(key, new SecretValidationResult(SecretValidationState.Active), DateTimeOffset.UtcNow.AddMinutes(5));

        WindowsAccessControlAssert.AllowsOnlyCurrentUser(temp.Path);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(Path.Combine(temp.Path, "entries"));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(Path.Combine(temp.Path, "locks"));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(GetSingleEntryPath(temp.Path));
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(GetSingleLockPath(temp.Path));
    }

    /// <summary>
    /// Verifies that cache fingerprints invalidate otherwise matching entries.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsDifferentCacheFingerprint()
    {
        using TempDirectory temp = TempDirectory.Create();
        Finding finding = CreateFinding();
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            finding,
            new Uri("https://api.github.com/user"));
        SecretValidationCache firstCache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCache secondCache = SecretValidationCache.Open(temp.Path, "rules:v2");
        firstCache.Write(
            key,
            new SecretValidationResult(SecretValidationState.Active),
            DateTimeOffset.UtcNow.AddMinutes(5));

        bool found = secondCache.TryRead(key, DateTimeOffset.UtcNow, out SecretValidationResult? result);

        Assert.IsFalse(found);
        Assert.IsNull(result);
    }

    /// <summary>
    /// Verifies that expired entries are not returned and can be pruned.
    /// </summary>
    [TestMethod]
    public void ExpiredEntriesAreMissesAndCanBePruned()
    {
        using TempDirectory temp = TempDirectory.Create();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));
        cache.Write(key, new SecretValidationResult(SecretValidationState.Inactive), now.AddSeconds(-1));

        bool found = cache.TryRead(key, now, out SecretValidationResult? result);
        int pruned = cache.PruneExpired(now);

        Assert.IsFalse(found);
        Assert.IsNull(result);
        Assert.AreEqual(1, pruned);
    }

    /// <summary>
    /// Verifies expired validation entries are pruned even when their fingerprint is stale.
    /// </summary>
    [TestMethod]
    public void PruneExpiredDeletesStaleFingerprintEntries()
    {
        using TempDirectory temp = TempDirectory.Create();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));
        SecretValidationCache staleCache = SecretValidationCache.Open(temp.Path, "rules:old");
        SecretValidationCache activeCache = SecretValidationCache.Open(temp.Path, "rules:new");
        staleCache.Write(key, new SecretValidationResult(SecretValidationState.Inactive), now.AddSeconds(-1));

        int pruned = activeCache.PruneExpired(now);

        Assert.AreEqual(1, pruned);
        Assert.IsEmpty(Directory.EnumerateFiles(temp.Path, "*.cache", SearchOption.AllDirectories));
    }

    /// <summary>
    /// Verifies that validation-cache maintenance removes unreadable authenticated entries.
    /// </summary>
    [TestMethod]
    public void PruneExpiredDeletesCorruptEntries()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "v1",
            CreateFinding(),
            new Uri("https://api.github.com/user"));
        cache.Write(key, new SecretValidationResult(SecretValidationState.Active), DateTimeOffset.UtcNow.AddMinutes(5));
        string entryPath = GetSingleEntryPath(temp.Path);
        File.WriteAllText(entryPath, "corrupt", new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        int pruned = cache.PruneExpired(DateTimeOffset.UtcNow);

        Assert.AreEqual(1, pruned);
        Assert.IsFalse(File.Exists(entryPath));
    }

    /// <summary>
    /// Verifies that callers cannot accidentally use raw secret material as the key secret hash.
    /// </summary>
    [TestMethod]
    public void CreateRejectsNonHashSecretKeyMaterial()
    {
        Assert.ThrowsExactly<ArgumentException>(() => SecretValidationCacheKey.Create(
            "github",
            "v1",
            "github-pat",
            CreateGitHubPat(),
            new Uri("https://api.github.com/user")));
    }

    private static string ReadCacheText(string rootPath)
    {
        var builder = new StringBuilder();
        foreach (string file in Directory.EnumerateFiles(rootPath, "*.cache", SearchOption.AllDirectories))
        {
            builder.Append(File.ReadAllText(file));
        }

        return builder.ToString();
    }

    private static string GetSingleEntryPath(string rootPath)
    {
        string[] entries = Directory.GetFiles(Path.Combine(rootPath, "entries"), "*.cache", SearchOption.AllDirectories);
        Assert.HasCount(1, entries);
        return entries[0];
    }

    private static string GetSingleLockPath(string rootPath)
    {
        string[] entries = Directory.GetFiles(Path.Combine(rootPath, "locks"), "*.lock", SearchOption.AllDirectories);
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

    private static Finding CreateFinding()
    {
        string secret = CreateGitHubPat();
        return new Finding(
            "github-pat",
            "GitHub token",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:github-pat:1");
    }

    private static string CreateGitHubPat()
    {
        return CreateGitHubClassicToken("ghp_");
    }

    private static string CreateGitHubClassicToken(string prefix)
    {
        return string.Concat(prefix, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
}
