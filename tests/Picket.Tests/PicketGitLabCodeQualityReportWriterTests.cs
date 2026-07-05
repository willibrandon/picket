using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketGitLabCodeQualityReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketGitLabCodeQualityReportWriterTests
{
    /// <summary>
    /// Verifies that empty findings produce an empty GitLab Code Quality array.
    /// </summary>
    [TestMethod]
    public void WriteReturnsEmptyArrayForNoFindings()
    {
        string json = PicketGitLabCodeQualityReportWriter.Write([]);

        Assert.AreEqual("[]\n", json);
    }

    /// <summary>
    /// Verifies that required GitLab Code Quality fields are written and escaped.
    /// </summary>
    [TestMethod]
    public void WriteIncludesRequiredFields()
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
            "src/app.cs",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "src/app.cs:rule:1");

        string json = PicketGitLabCodeQualityReportWriter.Write([finding]);

        Assert.Contains("\"description\":\"rule: desc\"", json);
        Assert.Contains("\"check_name\":\"rule\"", json);
        Assert.Contains("\"fingerprint\":\"src/app.cs:rule:1:2\"", json);
        Assert.Contains("\"severity\":\"critical\"", json);
        Assert.Contains("\"location\":{\"path\":\"src/app.cs\",\"lines\":{\"begin\":1}}", json);
    }

    /// <summary>
    /// Verifies that symlink display paths and safe fallback fingerprints are used.
    /// </summary>
    [TestMethod]
    public void WriteUsesSymlinkPathAndFallbackFingerprint()
    {
        var finding = new Finding(
            "rule",
            string.Empty,
            3,
            3,
            5,
            11,
            "match",
            "secret",
            "target.txt",
            "link.txt",
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            string.Empty);

        string json = PicketGitLabCodeQualityReportWriter.Write([finding]);

        Assert.Contains("\"description\":\"rule detected a secret in link.txt on line 3.\"", json);
        Assert.Contains("\"fingerprint\":\"link.txt:rule:3:5\"", json);
        Assert.Contains("\"location\":{\"path\":\"link.txt\",\"lines\":{\"begin\":3}}", json);
    }
}
