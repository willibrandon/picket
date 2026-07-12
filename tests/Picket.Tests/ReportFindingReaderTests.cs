using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using System.Text.Json.Nodes;

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
    /// Verifies Picket JSON Lines round-trips explainable randomness metadata.
    /// </summary>
    [TestMethod]
    public void TryReadPreservesPicketRandomnessMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "a8F2kL9mQ4xT7vN1zR6pW3cY", includeRandomness: true);
        string report = PicketJsonlReportWriter.Write([finding]);
        string reportPath = WriteReport(root.Path, "report.jsonl", report);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsTrue(read);
        Assert.IsNotNull(findings);
        Assert.HasCount(1, findings);
        SecretRandomnessAssessment assessment = findings[0].Randomness
            ?? throw new InvalidOperationException("Report finding did not preserve randomness metadata.");
        Assert.AreEqual(0.902542, assessment.Score);
        Assert.AreEqual("likely-random", assessment.Classification);
        Assert.AreEqual("alphanumeric", assessment.Features.Alphabet);
        Assert.Contains("balanced-character-classes", assessment.Signals);
        Assert.Contains("\"randomness\":{", report);
        Assert.DoesNotContain("randomnessSample", report);
    }

    /// <summary>
    /// Verifies out-of-range randomness scores make a report invalid without escaping exceptions.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsOutOfRangeRandomnessScore()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "a8F2kL9mQ4xT7vN1zR6pW3cY", includeRandomness: true);
        string report = PicketJsonlReportWriter.Write([finding]).Replace(
            "\"score\":0.902542",
            "\"score\":2",
            StringComparison.Ordinal);
        string reportPath = WriteReport(root.Path, "report.jsonl", report);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
    }

    /// <summary>
    /// Verifies non-object randomness metadata makes a report invalid without escaping exceptions.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsNonObjectRandomnessMetadata()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "a8F2kL9mQ4xT7vN1zR6pW3cY", includeRandomness: true);
        JsonObject report = JsonNode.Parse(PicketJsonlReportWriter.Write([finding]))!.AsObject();
        report["randomness"] = "invalid";
        string reportPath = WriteReport(root.Path, "report.jsonl", report.ToJsonString());

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
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

    /// <summary>
    /// Verifies that truncated JSON reports are rejected without escaping parser exceptions.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsTruncatedJsonReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            {"schema":"picket.report.v1","findings":[
            """);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
    }

    /// <summary>
    /// Verifies that malformed JSON Lines reports are rejected without returning partial findings.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsMalformedJsonLinesReport()
    {
        using TempDirectory root = TempDirectory.Create();
        Finding finding = CreateFinding("picket-rule", "auth.py", "secret-value");
        string reportPath = WriteReport(
            root.Path,
            "report.jsonl",
            string.Concat(
                PicketJsonlReportWriter.Write([finding]),
                "{\"schema\":\"picket.finding.v1\""));

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
    }

    /// <summary>
    /// Verifies that unsupported JSON object shapes are rejected.
    /// </summary>
    [TestMethod]
    public void TryReadRejectsUnsupportedJsonObjectShape()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            {"schema":"picket.report.v1","findings":{}}
            """);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsFalse(read);
        Assert.IsNull(findings);
    }

    /// <summary>
    /// Verifies that type-confused finding fields degrade to defaults instead of throwing.
    /// </summary>
    [TestMethod]
    public void TryReadTreatsTypeConfusedFindingFieldsAsDefaults()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = WriteReport(
            root.Path,
            "report.json",
            """
            {
              "schema": "picket.report.v1",
              "findings": [
                {
                  "schema": "picket.finding.v1",
                  "ruleId": "picket-rule",
                  "description": { "value": "wrong type" },
                  "startLine": "not-a-number",
                  "endLine": 9223372036854775807,
                  "startColumn": true,
                  "endColumn": null,
                  "match": ["wrong"],
                  "secret": 123,
                  "file": "auth.py",
                  "entropy": "not-a-double",
                  "tags": "tag"
                }
              ]
            }
            """);

        bool read = ReportFindingReader.TryRead(reportPath, out List<Finding>? findings);

        Assert.IsTrue(read);
        Assert.IsNotNull(findings);
        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-rule", findings[0].RuleID);
        Assert.AreEqual("auth.py", findings[0].File);
        Assert.IsEmpty(findings[0].Description);
        Assert.AreEqual(0, findings[0].StartLine);
        Assert.AreEqual(0, findings[0].EndLine);
        Assert.AreEqual(0, findings[0].StartColumn);
        Assert.AreEqual(0, findings[0].EndColumn);
        Assert.IsEmpty(findings[0].Match);
        Assert.IsEmpty(findings[0].Secret);
        Assert.AreEqual(0, findings[0].Entropy);
        Assert.IsEmpty(findings[0].Tags);
    }

    private static string WriteReport(string root, string fileName, string contents)
    {
        string reportPath = Path.Combine(root, fileName);
        File.WriteAllText(reportPath, contents);
        return reportPath;
    }

    private static Finding CreateFinding(string ruleId, string file, string secret, bool includeRandomness = false)
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
            $"line containing {secret}",
            randomness: includeRandomness ? SecretRandomnessScorer.Assess(secret) : null);
    }
}
