using System.Security.Cryptography;
using System.Text;
using Picket.Sources;

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

    private static string ComputeSha256(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
}
