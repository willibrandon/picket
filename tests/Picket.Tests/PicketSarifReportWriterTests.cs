using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketSarifReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketSarifReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies the native SARIF empty report shape and Picket tool identity.
    /// </summary>
    [TestMethod]
    public void WriteReturnsPicketEmptyReportShape()
    {
        string sarif = PicketSarifReportWriter.Write([], []);

        Assert.Contains("\"name\": \"picket\"", sarif);
        Assert.Contains("\"fullName\": \"Picket secrets scanner\"", sarif);
        Assert.Contains("\"informationUri\": \"https://github.com/willibrandon/picket\"", sarif);
        Assert.Contains("\"rules\": []", sarif);
        Assert.Contains("\"results\": []", sarif);
    }

    /// <summary>
    /// Verifies native SARIF rule and finding metadata for code scanning.
    /// </summary>
    [TestMethod]
    public void WriteUsesPicketSarifShape()
    {
        Finding finding = CreateFinding();
        SecretRule rule = SecretRule.Create(
            "test-rule",
            "A test rule",
            "secret",
            tags: ["credential"],
            severity: "high",
            confidence: "medium",
            rulePack: "picket-strict",
            provider: "example",
            documentationUrl: "https://example.invalid/rules/test-rule");

        string sarif = PicketSarifReportWriter.Write([finding], [rule]);

        Assert.Contains("\"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\"", sarif);
        Assert.Contains("\"version\": \"2.1.0\"", sarif);
        Assert.Contains("\"id\": \"test-rule\"", sarif);
        Assert.Contains("\"level\": \"error\"", sarif);
        Assert.Contains("\"precision\": \"medium\"", sarif);
        Assert.Contains("\"security-severity\": \"7.0\"", sarif);
        Assert.Contains("\"rulePack\": \"picket-strict\"", sarif);
        Assert.Contains("\"provider\": \"example\"", sarif);
        Assert.Contains("\"documentationUrl\": \"https://example.invalid/rules/test-rule\"", sarif);
        Assert.Contains("\"credential\",\n         \"security\",\n         \"secrets\"", sarif);
        Assert.Contains("\"ruleId\": \"test-rule\"", sarif);
        Assert.Contains("\"kind\": \"fail\"", sarif);
        Assert.Contains("\"text\": \"test-rule: A test rule detected a secret in auth.py on line 1.\"", sarif);
        Assert.Contains("\"uri\": \"auth.py\"", sarif);
        Assert.Contains("\"snippet\": {\n          \"text\": \"line containing secret\"\n         }", sarif);
        Assert.Contains("\"picketFingerprint\": \"auth.py:test-rule:1:1\"", sarif);
        Assert.Contains("\"schema\": \"picket.finding.v1\"", sarif);
        Assert.Contains("\"fingerprint\": \"auth.py:test-rule:1:1\"", sarif);
        Assert.Contains("\"entropy\": 2.5", sarif);
        Assert.Contains("\"secretSha256\": \"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\"", sarif);
        Assert.Contains("\"matchSha256\": \"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\"", sarif);
        Assert.Contains($"\"blobSha256\": \"{BlobSha256}\"", sarif);
        Assert.Contains("\"validationState\": \"unknown\"", sarif);
        Assert.Contains("\"severity\": \"high\"", sarif);
        Assert.Contains("\"confidence\": \"medium\"", sarif);
        Assert.Contains("\"provenanceType\": \"git\"", sarif);
        Assert.Contains("\"baselineStatus\": \"new\"", sarif);
        Assert.Contains("\"decodePath\": [", sarif);
        Assert.Contains("\"base64\"", sarif);
        Assert.Contains("\"remediationLinks\": [\n       \"https://example.invalid/rules/test-rule\"\n      ]", sarif);
    }

    /// <summary>
    /// Verifies that symlink paths and safe fallback fingerprints are used.
    /// </summary>
    [TestMethod]
    public void WriteUsesSymlinkPathAndFallbackFingerprint()
    {
        Finding finding = CreateFinding(symlinkFile: "link.py", fingerprint: string.Empty);

        string sarif = PicketSarifReportWriter.Write([finding], []);

        Assert.Contains("\"uri\": \"link.py\"", sarif);
        Assert.Contains("\"picketFingerprint\": \"link.py:test-rule:1:1\"", sarif);
    }

    private static Finding CreateFinding(string symlinkFile = "", string fingerprint = "fingerprint")
    {
        return new Finding(
            "test-rule",
            "A test rule",
            1,
            2,
            1,
            2,
            "secret",
            "secret",
            "auth.py",
            symlinkFile,
            "0000000000000000",
            2.5,
            "John Doe",
            "johndoe@example.com",
            "2026-07-05",
            "commit message",
            ["tag1", "tag2"],
            fingerprint,
            "line containing secret",
            "https://github.com/example/repo/blob/commit/auth.py#L1",
            blobSha256: BlobSha256,
            decodePath: ["base64"]);
    }
}
