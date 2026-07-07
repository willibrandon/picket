using Picket.Engine;
using Picket.Verify;
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
        Assert.Contains("picket.validation-cache.v1", storedText);
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
