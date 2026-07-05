using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksCsvReportWriter" />.
/// </summary>
[TestClass]
public sealed class GitleaksCsvReportWriterTests
{
    /// <summary>
    /// Verifies that Gitleaks writes no CSV bytes for an empty finding set.
    /// </summary>
    [TestMethod]
    public void WriteReturnsEmptyStringForNoFindings()
    {
        string csv = GitleaksCsvReportWriter.Write([]);

        Assert.IsEmpty(csv);
    }

    /// <summary>
    /// Verifies the Gitleaks CSV column order and tag formatting.
    /// </summary>
    [TestMethod]
    public void WriteUsesGitleaksColumnOrder()
    {
        Finding finding = CreateFinding();

        string csv = GitleaksCsvReportWriter.Write([finding]);

        Assert.Contains("RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags\n", csv);
        Assert.Contains("test-rule,0000000000000000,auth.py,,a secret,line containing secret,1,2,1,2,John Doe,opps,10-19-2003,johndoe@gmail.com,fingerprint,tag1 tag2 tag3\n", csv);
    }

    /// <summary>
    /// Verifies RFC 4180 escaping used by Gitleaks' Go CSV writer.
    /// </summary>
    [TestMethod]
    public void WriteEscapesCsvFields()
    {
        Finding finding = CreateFinding(secret: "a, \"secret\"", match: "line\ncontaining secret");

        string csv = GitleaksCsvReportWriter.Write([finding]);

        Assert.Contains("\"a, \"\"secret\"\"\"", csv);
        Assert.Contains("\"line\ncontaining secret\"", csv);
    }

    private static Finding CreateFinding(
        string secret = "a secret",
        string match = "line containing secret")
    {
        return new Finding(
            "test-rule",
            string.Empty,
            1,
            2,
            1,
            2,
            match,
            secret,
            "auth.py",
            string.Empty,
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
