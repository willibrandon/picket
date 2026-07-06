using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="ReportFindingReader" />.
/// </summary>
[TestClass]
public sealed class ReportFindingReaderTests
{
    /// <summary>
    /// Verifies that Picket JSON reports can be read as findings.
    /// </summary>
    [TestMethod]
    public void TryReadReadsPicketJsonReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "secret-value");
        SecretRule rule = SecretRule.Create("picket-rule", "desc", "secret");
        string reportPath = WriteReport(root.Path, "report.json", PicketJsonReportWriter.Write([finding], [rule]));

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsTrue(read);
        Assert.IsNotNull(findings);
        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-rule", findings[0].RuleID);
        Assert.AreEqual("auth.py", findings[0].File);
        Assert.AreEqual("secret-value", findings[0].Secret);
        Assert.AreEqual(StableFindingFingerprint.Create(finding), findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that Picket JSON Lines reports can be read as findings.
    /// </summary>
    [TestMethod]
    public void TryReadReadsPicketJsonLinesReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding first = CreateFinding("first-rule", "first.py", "first-secret");
        Finding second = CreateFinding("second-rule", "second.py", "second-secret");
        string reportPath = WriteReport(root.Path, "report.jsonl", PicketJsonlReportWriter.Write([first, second]));

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsTrue(read);
        Assert.IsNotNull(findings);
        Assert.HasCount(2, findings);
        Assert.AreEqual("first-secret", findings[0].Secret);
        Assert.AreEqual("second-secret", findings[1].Secret);
    }

    /// <summary>
    /// Verifies that Gitleaks JSON reports can be read as findings.
    /// </summary>
    [TestMethod]
    public void TryReadReadsGitleaksJsonReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("gitleaks-rule", "auth.py", "secret-value");
        string reportPath = WriteReport(root.Path, "gitleaks.json", GitleaksJsonReportWriter.Write([finding]));

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsTrue(read);
        Assert.IsNotNull(findings);
        Assert.HasCount(1, findings);
        Assert.AreEqual("gitleaks-rule", findings[0].RuleID);
        Assert.AreEqual("auth.py", findings[0].File);
        Assert.AreEqual("auth.py:gitleaks-rule:1", findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that summary-only report formats are not treated as finding input.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsSummaryOnlyReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.sarif",
            """
            {"version":"2.1.0","runs":[]}
            """);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
    }

    private static string WriteReport(string root, string fileName, string contents)
    {
        string reportPath = Path.Combine(root, fileName);
        File.WriteAllText(reportPath, contents);
        return reportPath;
    }

    private static Finding CreateFinding(string ruleId, string file, string secret)
    {
        return new Finding(
            ruleId,
            "desc",
            1,
            1,
            2,
            7,
            secret,
            secret,
            file,
            string.Empty,
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["tag"],
            $"{file}:{ruleId}:1",
            $"line containing {secret}");
    }
}
