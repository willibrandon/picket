using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketJsonlReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketJsonlReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies that native JSONL writes no bytes for an empty finding set.
    /// </summary>
    [TestMethod]
    public void WriteReturnsEmptyStringForNoFindings()
    {
        string jsonl = PicketJsonlReportWriter.Write([]);

        Assert.IsEmpty(jsonl);
    }

    /// <summary>
    /// Verifies that each finding is written as one compact JSON object line.
    /// </summary>
    [TestMethod]
    public void WriteUsesOneLinePerFinding()
    {
        Finding first = CreateFinding("first-rule", "first.py");
        Finding second = CreateFinding("second-rule", "second.py");

        string jsonl = PicketJsonlReportWriter.Write([first, second]);
        string[] lines = jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.HasCount(2, lines);
        Assert.Contains("\"ruleId\":\"first-rule\"", lines[0]);
        Assert.Contains("\"file\":\"second.py\"", lines[1]);
    }

    /// <summary>
    /// Verifies native JSONL escaping and stable schema fields.
    /// </summary>
    [TestMethod]
    public void WriteEscapesStringsAndWritesNativeFields()
    {
        Finding finding = CreateFinding(
            "rule",
            "stdin",
            match: "x=\"y\"\nnext",
            secret: "secret",
            tags: ["tag1", "tag2"],
            link: "https://github.com/example/repo/blob/commit/stdin#L1");

        string jsonl = PicketJsonlReportWriter.Write([finding]);

        Assert.Contains("\"schema\":\"picket.finding.v1\"", jsonl);
        Assert.Contains("\"match\":\"x=\\\"y\\\"\\nnext\"", jsonl);
        Assert.Contains("\"secretSha256\":\"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\"", jsonl);
        Assert.Contains("\"matchSha256\":\"c67137832a0e4df13a1f667166b91ffe010134d01578d7bd6499c36def655d6b\"", jsonl);
        Assert.Contains($"\"blobSha256\":\"{BlobSha256}\"", jsonl);
        Assert.Contains("\"tags\":[\"tag1\",\"tag2\"]", jsonl);
        Assert.Contains("\"fingerprint\":\"stdin:rule:1:1\"", jsonl);
        Assert.Contains("\"validationState\":\"unknown\"", jsonl);
        Assert.Contains("\"severity\":\"critical\"", jsonl);
        Assert.Contains("\"confidence\":\"high\"", jsonl);
        Assert.Contains("\"rulePack\":\"\"", jsonl);
        Assert.Contains("\"provider\":\"\"", jsonl);
        Assert.Contains("\"documentationUrl\":\"\"", jsonl);
        Assert.Contains("\"provenance\":{\"type\":\"git\",\"path\":\"stdin\",\"commit\":\"0000000000000000\"}", jsonl);
        Assert.Contains("\"decodePath\":[\"base64\"]", jsonl);
        Assert.Contains("\"remediationLinks\":[]", jsonl);
        Assert.Contains("\"link\":\"https://github.com/example/repo/blob/commit/stdin#L1\"", jsonl);
    }

    /// <summary>
    /// Verifies JSONL can resolve native rule metadata when rules are supplied.
    /// </summary>
    [TestMethod]
    public void WriteUsesRuleMetadataWhenRulesAreSupplied()
    {
        Finding finding = CreateFinding("rule", "stdin");
        SecretRule rule = SecretRule.Create(
            "rule",
            "desc",
            "secret",
            severity: "high",
            confidence: "medium",
            rulePack: "picket-strict",
            provider: "example",
            documentationUrl: "https://example.invalid/rules/rule");

        string jsonl = PicketJsonlReportWriter.Write([finding], [rule]);

        Assert.Contains("\"severity\":\"high\"", jsonl);
        Assert.Contains("\"confidence\":\"medium\"", jsonl);
        Assert.Contains("\"rulePack\":\"picket-strict\"", jsonl);
        Assert.Contains("\"provider\":\"example\"", jsonl);
        Assert.Contains("\"remediationLinks\":[\"https://example.invalid/rules/rule\"]", jsonl);
    }

    private static Finding CreateFinding(
        string ruleId,
        string file,
        string match = "line containing secret",
        string secret = "a secret",
        IReadOnlyList<string>? tags = null,
        string link = "")
    {
        return new Finding(
            ruleId,
            "desc",
            1,
            2,
            1,
            2,
            match,
            secret,
            file,
            string.Empty,
            "0000000000000000",
            2.5,
            "John Doe",
            "johndoe@example.com",
            "10-19-2003",
            "opps",
            tags ?? [],
            "fingerprint",
            link: link,
            blobSha256: BlobSha256,
            decodePath: ["base64"]);
    }
}
