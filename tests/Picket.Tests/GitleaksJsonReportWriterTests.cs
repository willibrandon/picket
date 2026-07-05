using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksJsonReportWriter" />.
/// </summary>
[TestClass]
public sealed class GitleaksJsonReportWriterTests
{
    /// <summary>
    /// Verifies the empty report shape.
    /// </summary>
    [TestMethod]
    public void WriteReturnsGitleaksEmptyArrayShape()
    {
        string json = GitleaksJsonReportWriter.Write([]);

        Assert.AreEqual("[]\n", json);
    }

    /// <summary>
    /// Verifies escaping and deterministic field order.
    /// </summary>
    [TestMethod]
    public void WriteEscapesStringsAndKeepsFieldOrder()
    {
        var finding = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            8,
            "x=\"y\"",
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

        string json = GitleaksJsonReportWriter.Write([finding]);

        Assert.Contains("\"RuleID\": \"rule\"", json);
        Assert.Contains("\"Match\": \"x=\\\"y\\\"\"", json);
        int ruleIdIndex = json.IndexOf("\"RuleID\"", StringComparison.Ordinal);
        int fingerprintIndex = json.IndexOf("\"Fingerprint\"", StringComparison.Ordinal);

        Assert.IsLessThan(fingerprintIndex, ruleIdIndex);
    }
}
