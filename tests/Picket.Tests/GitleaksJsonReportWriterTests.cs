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

    /// <summary>
    /// Verifies that non-empty tag arrays use Gitleaks JSON indentation.
    /// </summary>
    [TestMethod]
    public void WriteFormatsNonEmptyTagsLikeGitleaks()
    {
        var finding = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            8,
            "x",
            "secret",
            "stdin",
            string.Empty,
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["one", "two"],
            "stdin:rule:1");

        string json = GitleaksJsonReportWriter.Write([finding]);

        string expectedTags = """
              "Tags": [
               "one",
               "two"
              ],
            """.ReplaceLineEndings("\n");

        Assert.Contains(expectedTags, json);
    }

    /// <summary>
    /// Verifies the Gitleaks object whitespace and float32 entropy formatting.
    /// </summary>
    [TestMethod]
    public void WriteUsesGitleaksObjectWhitespaceAndEntropyPrecision()
    {
        var finding = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            8,
            "x",
            "secret",
            "stdin",
            string.Empty,
            string.Empty,
            3.681880802803402,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "stdin:rule:1");

        string json = GitleaksJsonReportWriter.Write([finding]);

        Assert.Contains("\"Entropy\": 3.6818807", json);
        Assert.Contains("\"Fingerprint\": \"stdin:rule:1\"\n }\n]\n", json);
        Assert.DoesNotContain("\"Fingerprint\": \"stdin:rule:1\"\n\n }", json);
    }

    /// <summary>
    /// Verifies that Gitleaks JSON includes Link only when it is present.
    /// </summary>
    [TestMethod]
    public void WriteOmitsEmptyLinkAndIncludesPresentLink()
    {
        var findingWithoutLink = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            8,
            "x",
            "secret",
            "stdin",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "stdin:rule:1");
        var findingWithLink = new Finding(
            "rule",
            "desc",
            1,
            1,
            2,
            8,
            "x",
            "secret",
            "stdin",
            string.Empty,
            "commit",
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "commit:stdin:rule:1",
            link: "https://github.com/example/repo/blob/commit/stdin#L1");

        string jsonWithoutLink = GitleaksJsonReportWriter.Write([findingWithoutLink]);
        string jsonWithLink = GitleaksJsonReportWriter.Write([findingWithLink]);

        Assert.DoesNotContain("\"Link\"", jsonWithoutLink);
        Assert.Contains("\"Link\": \"https://github.com/example/repo/blob/commit/stdin#L1\"", jsonWithLink);
    }
}
