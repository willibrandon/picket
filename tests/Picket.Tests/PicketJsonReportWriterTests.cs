using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketJsonReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketJsonReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies that native JSON writes schema, tool, rule, and empty finding metadata.
    /// </summary>
    [TestMethod]
    public void WriteIncludesSchemaAndRulesForNoFindings()
    {
        SecretRule rule = SecretRule.Create("token", string.Empty, "token-[0-9]+", tags: ["secret"]);

        string json = PicketJsonReportWriter.Write([], [rule]);

        Assert.Contains("\"schema\":\"picket.report.v1\"", json);
        Assert.Contains("\"tool\":{\"name\":\"picket\"}", json);
        Assert.Contains("\"rules\":[{\"id\":\"token\"", json);
        Assert.Contains("\"tags\":[\"secret\"]", json);
        Assert.Contains("\"findings\":[]", json);
    }

    /// <summary>
    /// Verifies native JSON escaping and finding metadata.
    /// </summary>
    [TestMethod]
    public void WriteEscapesStringsAndWritesFindings()
    {
        SecretRule rule = SecretRule.Create("rule", string.Empty, "x", keywords: ["x"], tags: ["tag"]);
        var finding = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            7,
            "x=\"y\"\nnext",
            "secret",
            "stdin",
            string.Empty,
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["tag"],
            "stdin:rule:1",
            blobSha256: BlobSha256,
            decodePath: ["base64"]);

        string json = PicketJsonReportWriter.Write([finding], [rule]);

        Assert.Contains("\"schema\":\"picket.finding.v1\"", json);
        Assert.Contains("\"match\":\"x=\\\"y\\\"\\nnext\"", json);
        Assert.Contains("\"secretSha256\":\"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b\"", json);
        Assert.Contains("\"matchSha256\":\"c67137832a0e4df13a1f667166b91ffe010134d01578d7bd6499c36def655d6b\"", json);
        Assert.Contains($"\"blobSha256\":\"{BlobSha256}\"", json);
        Assert.Contains("\"keywords\":[\"x\"]", json);
        Assert.Contains("\"fingerprint\":\"stdin:rule:1:2\"", json);
        Assert.Contains("\"validationState\":\"unknown\"", json);
        Assert.Contains("\"severity\":\"critical\"", json);
        Assert.Contains("\"confidence\":\"high\"", json);
        Assert.Contains("\"provenance\":{\"type\":\"filesystem\",\"path\":\"stdin\",\"commit\":\"\"}", json);
        Assert.Contains("\"decodePath\":[\"base64\"]", json);
        Assert.Contains("\"baselineStatus\":\"new\"", json);
        Assert.Contains("\"ignoreReason\":\"\"", json);
        Assert.Contains("\"remediationLinks\":[]", json);
    }

    /// <summary>
    /// Verifies native JSON honors validation states already attached to findings.
    /// </summary>
    [TestMethod]
    public void WriteUsesAttachedValidationState()
    {
        SecretRule rule = SecretRule.Create("github-pat", string.Empty, "ghp_[0-9A-Za-z]{36}");
        string secret = string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        var finding = new Finding(
            "github-pat",
            string.Empty,
            1,
            1,
            1,
            40,
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
            "secret.txt:github-pat:1",
            validationState: "structurally-valid");

        string json = PicketJsonReportWriter.Write([finding], [rule]);

        Assert.Contains("\"validationState\":\"structurally-valid\"", json);
    }
}
