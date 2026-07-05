using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketJunitReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketJunitReportWriterTests
{
    /// <summary>
    /// Verifies the native JUnit empty report shape.
    /// </summary>
    [TestMethod]
    public void WriteReturnsPicketEmptyReportShape()
    {
        string xml = PicketJunitReportWriter.Write([]);

        Assert.Contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", xml);
        Assert.Contains("<testsuite failures=\"0\" name=\"picket\" tests=\"0\" time=\"\">", xml);
        Assert.Contains("<property name=\"schema\" value=\"picket.junit.v1\"></property>", xml);
        Assert.Contains("<property name=\"tool\" value=\"picket\"></property>", xml);
        Assert.DoesNotContain("name=\"gitleaks\"", xml);
    }

    /// <summary>
    /// Verifies native JUnit suite, case, failure, and embedded finding JSON.
    /// </summary>
    [TestMethod]
    public void WriteUsesPicketJunitShape()
    {
        Finding finding = CreateFinding();

        string xml = PicketJunitReportWriter.Write([finding]);

        Assert.Contains("<testsuite failures=\"1\" name=\"picket\" tests=\"1\" time=\"\">", xml);
        Assert.Contains("<testcase classname=\"test-rule\" file=\"auth.py\" name=\"test-rule: Test Rule detected a secret in auth.py on line 1.\" time=\"\">", xml);
        Assert.Contains("<failure message=\"test-rule: Test Rule detected a secret in auth.py on line 1.\" type=\"picket.finding.v1\">", xml);
        Assert.Contains("{&#34;schema&#34;:&#34;picket.finding.v1&#34;,&#34;ruleId&#34;:&#34;test-rule&#34;", xml);
        Assert.Contains("&#34;fingerprint&#34;:&#34;fingerprint&#34;", xml);
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

        string xml = PicketJunitReportWriter.Write([finding]);

        Assert.Contains("file=\"auth&amp;config.py\"", xml);
        Assert.Contains("name=\"test-rule: A &#34;quoted&#34; &lt;rule&gt; detected a secret in auth&amp;config.py on line 1.\"", xml);
        Assert.Contains("message=\"test-rule: A &#34;quoted&#34; &lt;rule&gt; detected a secret in auth&amp;config.py on line 1.\"", xml);
        Assert.Contains("line \\&#34;containing\\&#34; &lt;secret&gt;", xml);
    }

    /// <summary>
    /// Verifies that symlink paths are used as the displayed location.
    /// </summary>
    [TestMethod]
    public void WriteUsesSymlinkLocationWhenPresent()
    {
        Finding finding = CreateFinding(symlinkFile: "link.py");

        string xml = PicketJunitReportWriter.Write([finding]);

        Assert.Contains("file=\"link.py\"", xml);
        Assert.Contains("detected a secret in link.py on line 1.", xml);
    }

    private static Finding CreateFinding(
        string description = "Test Rule",
        string file = "auth.py",
        string symlinkFile = "",
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
            symlinkFile,
            "0000000000000000",
            0,
            "John Doe",
            "johndoe@example.com",
            "2026-07-05",
            "message",
            [],
            "fingerprint");
    }
}
