using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksSarifReportWriter" />.
/// </summary>
[TestClass]
public sealed class GitleaksSarifReportWriterTests
{
    /// <summary>
    /// Verifies the Gitleaks SARIF empty arrays and tool identity.
    /// </summary>
    [TestMethod]
    public void WriteReturnsGitleaksEmptyReportShape()
    {
        string sarif = GitleaksSarifReportWriter.Write([], []);

        Assert.Contains("\"name\": \"gitleaks\"", sarif);
        Assert.Contains("\"semanticVersion\": \"v8.0.0\"", sarif);
        Assert.Contains("\"informationUri\": \"https://github.com/gitleaks/gitleaks\"", sarif);
        Assert.Contains("\"rules\": []", sarif);
        Assert.Contains("\"results\": []", sarif);
    }

    /// <summary>
    /// Verifies Gitleaks SARIF rule metadata and finding result shape.
    /// </summary>
    [TestMethod]
    public void WriteUsesGitleaksSarifShape()
    {
        Finding finding = CreateFinding();
        SecretRule rule = SecretRule.Create("test-rule", "A test rule", "secret");

        string sarif = GitleaksSarifReportWriter.Write([finding], [rule]);

        Assert.Contains("\"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\"", sarif);
        Assert.Contains("\"version\": \"2.1.0\"", sarif);
        Assert.Contains("\"id\": \"test-rule\"", sarif);
        Assert.Contains("\"shortDescription\": {\n        \"text\": \"A test rule\"\n       }", sarif);
        Assert.Contains("\"text\": \"test-rule has detected secret for file auth.py at commit 0000000000000000.\"", sarif);
        Assert.Contains("\"ruleId\": \"test-rule\"", sarif);
        Assert.Contains("\"uri\": \"auth.py\"", sarif);
        Assert.Contains("\"startLine\": 1", sarif);
        Assert.Contains("\"snippet\": {\n          \"text\": \"a secret\"\n         }", sarif);
        Assert.Contains("\"commitSha\": \"0000000000000000\"", sarif);
        Assert.Contains("\"tags\": [\n       \"tag1\",\n       \"tag2\",\n       \"tag3\"\n      ]", sarif);
    }

    /// <summary>
    /// Verifies that SARIF locations prefer the symlink target when present.
    /// </summary>
    [TestMethod]
    public void WriteUsesSymlinkFileLocationWhenPresent()
    {
        Finding finding = CreateFinding(symlinkFile: "target.py");

        string sarif = GitleaksSarifReportWriter.Write([finding], []);

        Assert.Contains("\"uri\": \"target.py\"", sarif);
    }

    private static Finding CreateFinding(string symlinkFile = "")
    {
        return new Finding(
            "test-rule",
            "A test rule",
            1,
            2,
            1,
            2,
            "line containing secret",
            "a secret",
            "auth.py",
            symlinkFile,
            "0000000000000000",
            0,
            "John Doe",
            "johndoe@gmail.com",
            "10-19-2003",
            "opps",
            ["tag1", "tag2", "tag3"],
            "fingerprint");
    }
}
