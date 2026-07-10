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
        Assert.AreEqual(2, summary.Findings[0].StartColumn);
        Assert.AreEqual(StableFindingFingerprint.Create(finding), summary.Findings[0].Fingerprint);
        AssertRandomness(summary.Findings[0]);
    }

    /// <summary>
    /// Verifies that Picket HTML reports are summarized from embedded non-secret metadata.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesPicketHtmlReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-html-rule", "auth.py", "auth.py:picket-html-rule:1");
        SecretRule rule = SecretRule.Create("picket-html-rule", "desc", "secret");
        string reportPath = WriteReport(root.Path, "report.html", PicketHtmlReportWriter.Write([finding], [rule]));

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("picket-html", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual(1, summary.FileCount);
        Assert.HasCount(1, summary.Findings);
        Assert.AreEqual("picket-html-rule", summary.Findings[0].RuleId);
        Assert.AreEqual("auth.py", summary.Findings[0].Path);
        Assert.AreEqual(1, summary.Findings[0].Line);
        Assert.AreEqual(2, summary.Findings[0].StartColumn);
        Assert.AreEqual(StableFindingFingerprint.Create(finding), summary.Findings[0].Fingerprint);
        AssertRandomness(summary.Findings[0]);
        Assert.DoesNotContain("secret-value", string.Concat(
            summary.Findings[0].RuleId,
            summary.Findings[0].Path,
            summary.Findings[0].Fingerprint));
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
        Assert.AreEqual(1, summary.Findings[0].Line);
        Assert.AreEqual(2, summary.Findings[0].StartColumn);
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
        Assert.AreEqual(2, summary.Findings[0].StartColumn);
        Assert.AreEqual("second.py", summary.Findings[1].Path);
        Assert.AreEqual(2, summary.Findings[1].StartColumn);
    }

    /// <summary>
    /// Verifies that TruffleHog JSONL reports are summarized without secret fields.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesTruffleHogJsonlReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "trufflehog.jsonl",
            """
            {"SourceMetadata":{"Data":{"Git":{"commit":"abc","file":"keys.txt","line":4,"column":11}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIASECRET","RawV2":"AKIASECRET:secret","Redacted":"AKIA********","ExtraData":{"account":"123"}}
            """);

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("trufflehog-jsonl", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual("AWS", summary.Findings[0].RuleId);
        Assert.AreEqual("keys.txt", summary.Findings[0].Path);
        Assert.AreEqual(4, summary.Findings[0].Line);
        Assert.AreEqual(11, summary.Findings[0].StartColumn);
        Assert.AreEqual("trufflehog:AWS:keys.txt:4", summary.Findings[0].Fingerprint);
        Assert.DoesNotContain("AKIASECRET", summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that TruffleHog JSON result wrappers are summarized.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesTruffleHogJsonResultsReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "trufflehog.json",
            """
            {"results":[{"SourceMetadata":{"Data":{"Filesystem":{"file":"config.env","line":9}}},"DetectorName":"Slack","Verified":false,"Redacted":"xoxb-********"}]}
            """);

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("trufflehog-json", summary.Format);
        Assert.AreEqual(1, summary.FindingCount);
        Assert.AreEqual("Slack", summary.Findings[0].RuleId);
        Assert.AreEqual("config.env", summary.Findings[0].Path);
        Assert.AreEqual(9, summary.Findings[0].Line);
        Assert.AreEqual(0, summary.Findings[0].StartColumn);
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
        Assert.AreEqual(StableFindingFingerprint.Create(finding), summary.Findings[0].Fingerprint);
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
        Assert.AreEqual(1, summary.Findings[0].Line);
        Assert.AreEqual(2, summary.Findings[0].StartColumn);
        Assert.AreEqual(StableFindingFingerprint.Create(finding), summary.Findings[0].Fingerprint);
        AssertRandomness(summary.Findings[0]);
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

    /// <summary>
    /// Verifies malformed reports with invalid line numbers fail with a format error.
    /// </summary>
    [TestMethod]
    public void ReadRejectsInvalidLineNumberAsMalformedReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            [{"RuleID":"rule","File":"secret.txt","StartLine":-1,"Fingerprint":"fp"}]
            """);

        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => ReportSummaryReader.Read(reportPath));

        Assert.Contains("format of the file", exception.Message);
    }

    /// <summary>
    /// Verifies type-confused string fields do not reject otherwise readable summaries.
    /// </summary>
    [TestMethod]
    public void ReadSummarizesReportWithNonStringScalarFields()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            [{"RuleID":123,"File":"secret.txt","StartLine":7,"Fingerprint":false}]
            """);

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("gitleaks-json", summary.Format);
        Assert.HasCount(1, summary.Findings);
        Assert.IsEmpty(summary.Findings[0].RuleId);
        Assert.AreEqual("secret.txt", summary.Findings[0].Path);
        Assert.AreEqual(7, summary.Findings[0].Line);
        Assert.IsEmpty(summary.Findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies type-confused line fields default to zero instead of rejecting otherwise readable summaries.
    /// </summary>
    [TestMethod]
    public void ReadTreatsNonNumericLineFieldsAsZero()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            [{"RuleID":"rule","File":"secret.txt","StartLine":false,"Fingerprint":"fp"}]
            """);

        ReportSummary summary = ReportSummaryReader.Read(reportPath);

        Assert.AreEqual("gitleaks-json", summary.Format);
        Assert.HasCount(1, summary.Findings);
        Assert.AreEqual(0, summary.Findings[0].Line);
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
            "line containing secret",
            randomness: SecretRandomnessScorer.Assess("secret-value"));
    }

    private static void AssertRandomness(ReportFindingSummary finding)
    {
        SecretRandomnessAssessment expected = SecretRandomnessScorer.Assess("secret-value");
        Assert.AreEqual(expected.Score, finding.RandomnessScore);
        Assert.AreEqual(expected.Classification, finding.RandomnessClassification);
        Assert.AreEqual(expected.Model, finding.RandomnessModel);
    }
}
