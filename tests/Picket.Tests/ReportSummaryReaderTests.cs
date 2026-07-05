using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="ReportSummaryReader" />.
/// </summary>
[TestClass]
public sealed class ReportSummaryReaderTests
{
    /// <summary>
    /// Verifies that Picket JSON reports are summarized without secret fields.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesPicketJsonReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "auth.py:picket-rule:1");
        SecretRule rule = SecretRule.Create("picket-rule", "desc", "secret");
        string reportPath = WriteReport(root.Path, "report.json", PicketJsonReportWriter.Write([finding], [rule]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("picket-json", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual(1, summary.FileCount);
        Assert.HasCount(1, summary.Findings);
        Assert.AreEqual("picket-rule", summary.Findings[0].RuleId);
        Assert.AreEqual("auth.py", summary.Findings[0].Path);
        Assert.AreEqual(1, summary.Findings[0].Line);
        Assert.AreEqual("auth.py:picket-rule:1", summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that Gitleaks JSON reports are summarized.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesGitleaksJsonReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("gitleaks-rule", "auth.py", "auth.py:gitleaks-rule:1");
        string reportPath = WriteReport(root.Path, "gitleaks.json", GitleaksJsonReportWriter.Write([finding]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("gitleaks-json", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual("gitleaks-rule", summary.Findings[0].RuleId);
        Assert.AreEqual("auth.py", summary.Findings[0].Path);
        Assert.AreEqual("auth.py:gitleaks-rule:1", summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that Picket JSONL reports are summarized.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesPicketJsonlReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding first = CreateFinding("first-rule", "first.py", "first.py:first-rule:1");
        Finding second = CreateFinding("second-rule", "second.py", "second.py:second-rule:1");
        string reportPath = WriteReport(root.Path, "report.jsonl", PicketJsonlReportWriter.Write([first, second]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("picket-jsonl", summary.Format);
        Assert.AreEqual(2, summary.FindingCount);
        Assert.AreEqual(2, summary.FileCount);
        Assert.AreEqual("first.py", summary.Findings[0].Path);
        Assert.AreEqual("second.py", summary.Findings[1].Path);
    }

    /// <summary>
    /// Verifies that GitLab Code Quality JSON reports are summarized.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesGitLabCodeQualityReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("gitlab-rule", "auth.py", "auth.py:gitlab-rule:1");
        string reportPath = WriteReport(root.Path, "gl-code-quality-report.json", PicketGitLabCodeQualityReportWriter.Write([finding]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("gitlab-code-quality", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual("gitlab-rule", summary.Findings[0].RuleId);
        Assert.AreEqual("auth.py", summary.Findings[0].Path);
        Assert.AreEqual("auth.py:gitlab-rule:1", summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that SARIF reports are summarized.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesSarifReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("sarif-rule", "auth.py", "auth.py:sarif-rule:1");
        SecretRule rule = SecretRule.Create("sarif-rule", "desc", "secret");
        string reportPath = WriteReport(root.Path, "report.sarif", PicketSarifReportWriter.Write([finding], [rule]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("sarif", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual("sarif-rule", summary.Findings[0].RuleId);
        Assert.AreEqual("auth.py", summary.Findings[0].Path);
        Assert.AreEqual("auth.py:sarif-rule:1", summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that unsupported reports fail with a format error.
    /// </summary>
    [TestMethod]
    public void ReadRejectsUnsupportedReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(root.Path, "report.json", "{}");

        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => ReportSummaryReader.Read(reportPath));

        Assert.Contains("format of the file", exception.Message);
    }

    private static string WriteReport(string root, string fileName, string contents)
    {
        string reportPath = Path.Combine(root, fileName);
        File.WriteAllText(reportPath, contents);
        return reportPath;
    }

    private static Finding CreateFinding(string ruleId, string file, string fingerprint)
    {
        return new Finding(
            ruleId,
            "desc",
            1,
            1,
            2,
            7,
            "secret-value",
            "secret-value",
            file,
            string.Empty,
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["tag"],
            fingerprint,
            "line containing secret");
    }
}
