using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketToonReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketToonReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies the empty TOON report shape.
    /// </summary>
    [TestMethod]
    public void WriteReturnsEmptyReportShape()
    {
        string toon = PicketToonReportWriter.Write([], []);

        Assert.Contains("schema: picket.report.v1", toon);
        Assert.Contains("tool:\n  name: picket", toon);
        Assert.Contains("summary:\n  findings: 0\n  rules: 0", toon);
        Assert.Contains("findings: []", toon);
        Assert.Contains("findingTags: []", toon);
        Assert.Contains("rules: []", toon);
        Assert.Contains("ruleKeywords: []", toon);
        Assert.Contains("ruleTags: []", toon);
        Assert.AreNotEqual('\n', toon[^1]);
    }

    /// <summary>
    /// Verifies tabular findings, rules, and metadata tables.
    /// </summary>
    [TestMethod]
    public void WriteUsesTabularNativeReportShape()
    {
        Finding finding = CreateFinding(tags: ["tag1", "tag2"]);
        SecretRule rule = SecretRule.Create(
            "rule",
            "desc",
            "token-[0-9]+",
            secretGroup: 1,
            entropy: 3.5,
            pathPattern: "src/.*",
            keywords: ["token"],
            tags: ["secret"],
            skipReport: true,
            severity: "high",
            confidence: "medium",
            rulePack: "picket-strict",
            provider: "example",
            documentationUrl: "https://example.invalid/rules/rule");

        string toon = PicketToonReportWriter.Write([finding], [rule]);
        string fingerprint = StableFindingFingerprint.Create(finding);

        Assert.Contains("findings[1]{schema,ruleId,description,file,symlinkFile,startLine,endLine,startColumn,endColumn,positionKind,match,secret,secretSha256,matchSha256,blobSha256,decodePath,line,commit,entropy,randomnessModel,randomnessScore,randomnessClassification,randomnessSampleOffset,randomnessSampleLength,randomnessAlphabet,randomnessLengthScore,randomnessNormalizedEntropy,randomnessExpectedDistinctRatio,randomnessTransitionDiversity,randomnessLongestRunRatio,randomnessSequentialPairRatio,randomnessRepeatedPatternRatio,randomnessCommonBigramRatio,randomnessCharacterClassBalance,randomnessEncodedTextSignal,randomnessPlaceholderSignal,randomnessSignals,author,email,date,message,fingerprint,validationState,severity,confidence,rulePack,provider,provenanceType,baselineStatus,ignoreReason,link}:", toon);
        Assert.Contains($"  picket.finding.v1,rule,desc,stdin,\"\",1,2,3,4,gitleaksUtf8BytesInclusive,line containing secret,secret,2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b,307aa91418c6be9b60a0de3bd843a2e3f206061b0674fc6171ad91025f1c0cb3,{BlobSha256},base64,line containing secret,\"\",2.5,", toon);
        Assert.Contains($"\"{fingerprint}\",unknown,high,medium,picket-strict,example,filesystem,new,\"\",\"\"", toon);
        Assert.Contains("findingTags[2]{findingIndex,tag}:\n  0,tag1\n  0,tag2", toon);
        Assert.Contains("rules[1]{id,description,pattern,pathPattern,secretGroup,entropy,randomnessThreshold,detector,severity,confidence,rulePack,provider,documentationUrl,skipReport}:\n  rule,desc,\"token-[0-9]+\",src/.*,1,3.5,0,\"\",high,medium,picket-strict,example,\"https://example.invalid/rules/rule\",true", toon);
        Assert.Contains("ruleKeywords[1]{ruleIndex,keyword}:\n  0,token", toon);
        Assert.Contains("ruleTags[1]{ruleIndex,tag}:\n  0,secret", toon);
    }

    /// <summary>
    /// Verifies TOON quoting and escaping for string values.
    /// </summary>
    [TestMethod]
    public void WriteQuotesAndEscapesStrings()
    {
        Finding finding = CreateFinding(
            match: "x=\"y\"\nnext",
            secret: "a,b",
            line: "x=\"y\"\nnext",
            tags: ["123", "true"]);

        string toon = PicketToonReportWriter.Write([finding], []);

        Assert.Contains("\"x=\\\"y\\\"\\nnext\"", toon);
        Assert.Contains("\"a,b\"", toon);
        Assert.Contains("findingTags[2]{findingIndex,tag}:\n  0,\"123\"\n  0,\"true\"", toon);
        Assert.DoesNotContain("\r\n", toon);
        Assert.AreNotEqual('\n', toon[^1]);
    }

    private static Finding CreateFinding(
        string match = "line containing secret",
        string secret = "secret",
        string line = "line containing secret",
        IReadOnlyList<string>? tags = null)
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
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            tags ?? [],
            "fingerprint",
            line,
            blobSha256: BlobSha256,
            decodePath: ["base64"]);
    }
}
