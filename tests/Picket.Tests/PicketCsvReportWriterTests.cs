using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketCsvReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketCsvReportWriterTests
{
    /// <summary>
    /// Verifies that native CSV includes a header even when there are no findings.
    /// </summary>
    [TestMethod]
    public void WriteReturnsHeaderForNoFindings()
    {
        string csv = PicketCsvReportWriter.Write([]);

        Assert.AreEqual("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,Match,Line,Commit,Entropy,Author,Email,Date,Message,Fingerprint,Tags,Link\n", csv);
    }

    /// <summary>
    /// Verifies native CSV column order and finding fields.
    /// </summary>
    [TestMethod]
    public void WriteUsesNativeColumnOrder()
    {
        Finding finding = CreateFinding();

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,Match,Line,Commit,Entropy,Author,Email,Date,Message,Fingerprint,Tags,Link\n", csv);
        Assert.Contains("picket.finding.v1,rule,desc,stdin,,1,2,3,4,secret,line containing secret,line containing secret,0000000000000000,2.5,John Doe,johndoe@example.com,2026-07-05,message,fingerprint,tag1 tag2,https://github.com/example/repo/blob/commit/stdin#L1\n", csv);
    }

    /// <summary>
    /// Verifies RFC 4180 escaping for native CSV fields.
    /// </summary>
    [TestMethod]
    public void WriteEscapesCsvFields()
    {
        Finding finding = CreateFinding(
            match: "x=\"y\"\nnext",
            secret: "a,b",
            line: "x=\"y\"\nnext");

        string csv = PicketCsvReportWriter.Write([finding]);

        Assert.Contains("\"a,b\",\"x=\"\"y\"\"\nnext\",\"x=\"\"y\"\"\nnext\"", csv);
    }

    private static Finding CreateFinding(
        string match = "line containing secret",
        string secret = "secret",
        string line = "line containing secret")
    {
        return new Finding(
            "rule",
            "desc",
            1,
            2,
            3,
            4,
            match,
            secret,
            "stdin",
            string.Empty,
            "0000000000000000",
            2.5,
            "John Doe",
            "johndoe@example.com",
            "2026-07-05",
            "message",
            ["tag1", "tag2"],
            "fingerprint",
            line,
            "https://github.com/example/repo/blob/commit/stdin#L1");
    }
}
