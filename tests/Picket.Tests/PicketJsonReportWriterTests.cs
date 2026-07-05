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
            "stdin:rule:1");

        string json = PicketJsonReportWriter.Write([finding], [rule]);

        Assert.Contains("\"schema\":\"picket.finding.v1\"", json);
        Assert.Contains("\"match\":\"x=\\\"y\\\"\\nnext\"", json);
        Assert.Contains("\"keywords\":[\"x\"]", json);
        Assert.Contains("\"fingerprint\":\"stdin:rule:1\"", json);
    }
}
