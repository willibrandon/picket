using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using System.Text.Json;

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
        Assert.Contains("\"executionSuccessful\": true", sarif);
        Assert.Contains("\"results\": []", sarif);
    }

    /// <summary>
    /// Verifies an interrupted scan is represented as an unsuccessful SARIF invocation.
    /// </summary>
    [TestMethod]
    public void WriteMarksIncompleteScan()
    {
        string sarif = PicketSarifReportWriter.Write([], [], scanComplete: false);
        using JsonDocument document = JsonDocument.Parse(sarif);
        JsonElement invocation = document.RootElement
            .GetProperty("runs")[0]
            .GetProperty("invocations")[0];

        Assert.IsFalse(invocation.GetProperty("executionSuccessful").GetBoolean());
        Assert.AreEqual(
            "Picket did not scan every requested input.",
            invocation.GetProperty("toolExecutionNotifications")[0].GetProperty("message").GetProperty("text").GetString());
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
        string fingerprint = StableFindingFingerprint.Create(finding);

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
        Assert.Contains($"\"picketFingerprint\": \"{fingerprint}\"", sarif);
        Assert.Contains("\"schema\": \"picket.finding.v1\"", sarif);
        Assert.Contains($"\"fingerprint\": \"{fingerprint}\"", sarif);
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
        Assert.Contains($"\"picketFingerprint\": \"{StableFindingFingerprint.Create(finding)}\"", sarif);
    }

    /// <summary>
    /// Verifies native SARIF reports render non-finite entropy values as valid JSON numbers.
    /// </summary>
    [TestMethod]
    public void WriteRendersNonFiniteEntropyAsValidJson()
    {
        Finding finding = CreateFinding(entropy: double.NegativeInfinity);

        string sarif = PicketSarifReportWriter.Write([finding], []);
        using JsonDocument document = JsonDocument.Parse(sarif);
        JsonElement result = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
        JsonElement properties = result.GetProperty("properties");

        Assert.AreEqual(0, properties.GetProperty("entropy").GetDouble());
        Assert.DoesNotContain("Infinity", sarif);
    }

    private static Finding CreateFinding(string symlinkFile = "", string fingerprint = "fingerprint", double entropy = 2.5)
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
            entropy,
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
