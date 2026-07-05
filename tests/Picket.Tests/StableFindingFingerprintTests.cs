using Picket.Engine;

namespace Picket.Tests;

/// <summary>
/// Tests stable Picket-native finding fingerprints.
/// </summary>
[TestClass]
public sealed class StableFindingFingerprintTests
{
    /// <summary>
    /// Verifies the stable fingerprint format and a fixed known vector.
    /// </summary>
    [TestMethod]
    public void CreateReturnsVersionedKnownVector()
    {
        Finding finding = CreateFinding(startLine: 1, startColumn: 2);

        string fingerprint = StableFindingFingerprint.Create(finding);

        Assert.AreEqual("picket:v1:", fingerprint[..10]);
        Assert.HasCount(74, fingerprint);
        Assert.AreEqual("picket:v1:ea9206ee38f27b7bcfede3e3e94fa7acdbd1f384eafddb075bf385633f1f4634", fingerprint);
        Assert.DoesNotContain(finding.Secret, fingerprint);
    }

    /// <summary>
    /// Verifies that native fingerprints do not churn when a finding moves in a file or commit history.
    /// </summary>
    [TestMethod]
    public void CreateIgnoresLineColumnAndCommit()
    {
        Finding original = CreateFinding(startLine: 1, startColumn: 2, commit: "old");
        Finding moved = CreateFinding(startLine: 40, startColumn: 9, commit: "new");

        Assert.AreEqual(StableFindingFingerprint.Create(original), StableFindingFingerprint.Create(moved));
    }

    /// <summary>
    /// Verifies that the logical path, rule, secret, and decode path are part of the fingerprint identity.
    /// </summary>
    [TestMethod]
    public void CreateChangesForIdentityFields()
    {
        string original = StableFindingFingerprint.Create(CreateFinding());

        Assert.AreNotEqual(original, StableFindingFingerprint.Create(CreateFinding(file: "other.txt")));
        Assert.AreNotEqual(original, StableFindingFingerprint.Create(CreateFinding(ruleId: "other-rule")));
        Assert.AreNotEqual(original, StableFindingFingerprint.Create(CreateFinding(secret: "other-secret")));
        Assert.AreNotEqual(original, StableFindingFingerprint.Create(CreateFinding(decodePath: ["hex"])));
    }

    /// <summary>
    /// Verifies that symlink paths are treated as the logical report path.
    /// </summary>
    [TestMethod]
    public void CreateUsesSymlinkPathWhenPresent()
    {
        Finding symlink = CreateFinding(file: "target.txt", symlinkFile: "link.txt");
        Finding logical = CreateFinding(file: "link.txt");

        Assert.AreEqual(StableFindingFingerprint.Create(logical), StableFindingFingerprint.Create(symlink));
    }

    private static Finding CreateFinding(
        string ruleId = "rule",
        string file = "src/app.txt",
        string symlinkFile = "",
        string secret = "secret",
        string commit = "",
        int startLine = 1,
        int startColumn = 1,
        IReadOnlyList<string>? decodePath = null)
    {
        return new Finding(
            ruleId,
            "description",
            startLine,
            startLine,
            startColumn,
            startColumn + secret.Length,
            secret,
            secret,
            file,
            symlinkFile,
            commit,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            $"{file}:{ruleId}:{startLine}",
            blobSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            decodePath: decodePath ?? ["base64"]);
    }
}
