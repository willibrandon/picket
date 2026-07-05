using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksJunitReportWriter" />.
/// </summary>
[TestClass]
public sealed class GitleaksJunitReportWriterTests
{
    /// <summary>
    /// Verifies the Gitleaks JUnit empty report shape.
    /// </summary>
    [TestMethod]
    public void WriteReturnsGitleaksEmptyReportShape()
    {
        string xml = GitleaksJunitReportWriter.Write([]);

        Assert.AreEqual(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<testsuites>\n"
            + "\t<testsuite failures=\"0\" name=\"gitleaks\" tests=\"0\" time=\"\"></testsuite>\n"
            + "</testsuites>",
            xml);
    }

    /// <summary>
    /// Verifies the Gitleaks JUnit suite, case, failure, and embedded JSON shape.
    /// </summary>
    [TestMethod]
    public void WriteUsesGitleaksJunitShape()
    {
        Finding finding = CreateFinding();

        string xml = GitleaksJunitReportWriter.Write([finding]);

        Assert.Contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", xml);
        Assert.Contains("<testsuite failures=\"1\" name=\"gitleaks\" tests=\"1\" time=\"\">", xml);
        Assert.Contains("<testcase classname=\"Test Rule\" file=\"auth.py\" name=\"test-rule has detected a secret in file auth.py, line 1, at commit 0000000000000000.\" time=\"\">", xml);
        Assert.Contains("<failure message=\"test-rule has detected a secret in file auth.py, line 1, at commit 0000000000000000.\" type=\"Test Rule\">", xml);
        Assert.Contains("{&#xA;&#x9;&#34;RuleID&#34;: &#34;test-rule&#34;,", xml);
        Assert.Contains("&#x9;&#34;Tags&#34;: [],", xml);
        Assert.Contains("&#x9;&#34;Fingerprint&#34;: &#34;fingerprint&#34;&#xA;}</failure>", xml);
    }

    /// <summary>
    /// Verifies XML escaping for attributes and failure character data.
    /// </summary>
    [TestMethod]
    public void WriteEscapesXml()
    {
        Finding finding = CreateFinding(
            description: "A \"quoted\" <rule>",
            file: "auth&config.py",
            match: "line \"containing\" <secret>");

        string xml = GitleaksJunitReportWriter.Write([finding]);

        Assert.Contains("classname=\"A &#34;quoted&#34; &lt;rule&gt;\"", xml);
        Assert.Contains("file=\"auth&amp;config.py\"", xml);
        Assert.Contains("type=\"A &#34;quoted&#34; &lt;rule&gt;\"", xml);
        Assert.Contains("line \\&#34;containing\\&#34; \\u003csecret\\u003e", xml);
    }

    private static Finding CreateFinding(
        string description = "Test Rule",
        string file = "auth.py",
        string match = "line containing secret")
    {
        return new Finding(
            "test-rule",
            description,
            1,
            2,
            1,
            2,
            match,
            "a secret",
            file,
            string.Empty,
            "0000000000000000",
            0,
            "John Doe",
            "johndoe@gmail.com",
            "10-19-2003",
            "opps",
            [],
            "fingerprint");
    }
}
