using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketCsvReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketCsvReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies that native CSV includes a header even when there are no findings.
    /// </summary>
    [TestMethod]
    public void WriteReturnsHeaderForNoFindings()
    {
        string csv = PicketCsvReportWriter.Write([]);

        Assert.AreEqual("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,SecretSha256,Match,MatchSha256,BlobSha256,DecodePath,Line,Commit,Entropy,RandomnessModel,RandomnessScore,RandomnessClassification,RandomnessSampleOffset,RandomnessSampleLength,RandomnessAlphabet,RandomnessLengthScore,RandomnessNormalizedEntropy,RandomnessExpectedDistinctRatio,RandomnessTransitionDiversity,RandomnessLongestRunRatio,RandomnessSequentialPairRatio,RandomnessRepeatedPatternRatio,RandomnessCommonBigramRatio,RandomnessCharacterClassBalance,RandomnessEncodedTextSignal,RandomnessPlaceholderSignal,RandomnessSignals,Author,Email,Date,Message,Fingerprint,ValidationState,Severity,Confidence,RulePack,Provider,DocumentationUrl,ProvenanceType,BaselineStatus,IgnoreReason,Tags,Link\n", csv);
    }

    /// <summary>
    /// Verifies native CSV column order and finding fields.
    /// </summary>
    [TestMethod]
    public void WriteUsesNativeColumnOrder()
    {
        Finding finding = CreateFinding();

        string csv = PicketCsvReportWriter.Write([finding]);
        string fingerprint = StableFindingFingerprint.Create(finding);

        Assert.Contains("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,SecretSha256,Match,MatchSha256,BlobSha256,DecodePath,Line,Commit,Entropy,RandomnessModel,RandomnessScore,RandomnessClassification,RandomnessSampleOffset,RandomnessSampleLength,RandomnessAlphabet,RandomnessLengthScore,RandomnessNormalizedEntropy,RandomnessExpectedDistinctRatio,RandomnessTransitionDiversity,RandomnessLongestRunRatio,RandomnessSequentialPairRatio,RandomnessRepeatedPatternRatio,RandomnessCommonBigramRatio,RandomnessCharacterClassBalance,RandomnessEncodedTextSignal,RandomnessPlaceholderSignal,RandomnessSignals,Author,Email,Date,Message,Fingerprint,ValidationState,Severity,Confidence,RulePack,Provider,DocumentationUrl,ProvenanceType,BaselineStatus,IgnoreReason,Tags,Link\n", csv);
        Assert.Contains($"picket.finding.v1,rule,desc,stdin,,1,2,3,4,secret,2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b,line containing secret,307aa91418c6be9b60a0de3bd843a2e3f206061b0674fc6171ad91025f1c0cb3,{BlobSha256},base64,line containing secret,0000000000000000,2.5,", csv);
        Assert.Contains($"John Doe,johndoe@example.com,2026-07-05,message,{fingerprint},unknown,critical,high,,,,git,new,,tag1 tag2,https://github.com/example/repo/blob/commit/stdin#L1\n", csv);
    }

    /// <summary>
    /// Verifies RFC 4180 escaping for native CSV fields.
    /// </summary>
    [TestMethod]
    public void WriteEscapesCsvFields()
    {
        Finding finding = CreateFinding(
            match: "x=\"y\"\nnext",
            secret: "a,b",
            line: "x=\"y\"\nnext");

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("\"a,b\"", csv);
        Assert.Contains("1eb7c54d52831bbfe8942af0b1c56b7409523a59ed6ca99c1174fef7eb32c1b5", csv);
        Assert.Contains("\"x=\"\"y\"\"\nnext\"", csv);
        Assert.Contains("c67137832a0e4df13a1f667166b91ffe010134d01578d7bd6499c36def655d6b", csv);
    }

    /// <summary>
    /// Verifies native CSV neutralizes spreadsheet formula prefixes in finding-controlled fields.
    /// </summary>
    [TestMethod]
    public void WriteNeutralizesFormulaPrefixes()
    {
        Finding finding = CreateFinding(
            match: "+match",
            secret: "=secret",
            line: "@line",
            author: "-author");

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("\"'=secret\"", csv);
        Assert.Contains("\"'+match\"", csv);
        Assert.Contains("\"'@line\"", csv);
        Assert.Contains("\"'-author\"", csv);
    }

    /// <summary>
    /// Verifies native CSV neutralizes spreadsheet formula prefixes hidden behind leading control characters.
    /// </summary>
    [TestMethod]
    public void WriteNeutralizesControlCharacterFormulaPrefixes()
    {
        Finding finding = CreateFinding(
            match: "\t=match",
            secret: "\r=secret");

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("\"'\t=match\"", csv);
        Assert.Contains("\"'\r=secret\"", csv);
    }

    /// <summary>
    /// Verifies formula neutralization applies to persisted randomness metadata.
    /// </summary>
    [TestMethod]
    public void WriteNeutralizesRandomnessFormulaPrefixes()
    {
        SecretRandomnessFeatures features = SecretRandomnessFeatures.Create(
            0,
            8,
            "@alphabet",
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            0.5);
        SecretRandomnessAssessment assessment = SecretRandomnessAssessment.Create(
            "=model",
            0.5,
            "+classification",
            features,
            ["-signal"]);
        Finding finding = CreateFinding(randomness: assessment);

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("\"'=model\"", csv);
        Assert.Contains("\"'+classification\"", csv);
        Assert.Contains("\"'@alphabet\"", csv);
        Assert.Contains("\"'-signal\"", csv);
    }

    /// <summary>
    /// Verifies CSV can resolve native rule metadata when rules are supplied.
    /// </summary>
    [TestMethod]
    public void WriteUsesRuleMetadataWhenRulesAreSupplied()
    {
        Finding finding = CreateFinding();
        SecretRule rule = SecretRule.Create(
            "rule",
            "desc",
            "secret",
            severity: "high",
            confidence: "medium",
            rulePack: "picket-strict",
            provider: "example",
            documentationUrl: "https://example.invalid/rules/rule");

        string csv = PicketCsvReportWriter.Write([finding], [rule]);

        Assert.Contains(",unknown,high,medium,picket-strict,example,https://example.invalid/rules/rule,git,new,", csv);
    }

    private static Finding CreateFinding(
        string match = "line containing secret",
        string secret = "secret",
        string line = "line containing secret",
        string author = "John Doe",
        SecretRandomnessAssessment? randomness = null)
    {
        return new Finding(
            "rule",
            "desc",
            1,
            2,
            3,
            4,
            match,
            secret,
            "stdin",
            string.Empty,
            "0000000000000000",
            2.5,
            author,
            "johndoe@example.com",
            "2026-07-05",
            "message",
            ["tag1", "tag2"],
            "fingerprint",
            line,
            "https://github.com/example/repo/blob/commit/stdin#L1",
            blobSha256: BlobSha256,
            decodePath: ["base64"],
            randomness: randomness);
    }
}
