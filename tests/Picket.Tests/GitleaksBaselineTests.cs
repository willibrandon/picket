using Picket.Compat;
using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksBaseline" />.
/// </summary>
[TestClass]
public sealed class GitleaksBaselineTests
{
    /// <summary>
    /// Verifies that baseline suppression ignores fingerprints and tags like Gitleaks.
    /// </summary>
    [TestMethod]
    public void FilterSuppressesFindingWithoutComparingFingerprintOrTags()
    {
        Finding finding = CreateFinding(fingerprint: "new-fingerprint", tags: ["new"]);
        Finding baselineFinding = CreateFinding(fingerprint: "old-fingerprint", tags: ["old"]);
        var baseline = new GitleaksBaseline([baselineFinding]);

        IReadOnlyList<Finding> filtered = baseline.Filter([finding]);

        Assert.IsEmpty(filtered);
    }

    /// <summary>
    /// Verifies that unredacted baseline suppression compares the match and secret fields.
    /// </summary>
    [TestMethod]
    public void FilterKeepsFindingWhenSecretDiffersWithoutRedaction()
    {
        Finding finding = CreateFinding(match: "token=new", secret: "new");
        Finding baselineFinding = CreateFinding(match: "token=old", secret: "old");
        var baseline = new GitleaksBaseline([baselineFinding]);

        IReadOnlyList<Finding> filtered = baseline.Filter([finding]);

        Assert.HasCount(1, filtered);
    }

    /// <summary>
    /// Verifies that redacted baseline suppression does not compare match or secret values.
    /// </summary>
    [TestMethod]
    public void FilterSuppressesRedactedFindingWithoutComparingSecret()
    {
        Finding finding = CreateFinding(match: "REDACTED", secret: "REDACTED");
        Finding baselineFinding = CreateFinding(match: "token=old", secret: "old");
        var baseline = new GitleaksBaseline([baselineFinding]);

        IReadOnlyList<Finding> filtered = baseline.Filter([finding], redactionPercent: 100);

        Assert.IsEmpty(filtered);
    }

    /// <summary>
    /// Verifies that a Gitleaks-shaped JSON report can be loaded as a baseline.
    /// </summary>
    [TestMethod]
    public void LoadReadsJsonReport()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"), "baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            Finding finding = CreateFinding();
            File.WriteAllText(path, GitleaksJsonReportWriter.Write([finding]));

            GitleaksBaseline baseline = GitleaksBaseline.Load(path);

            Assert.AreEqual(1, baseline.Count);
            Assert.IsFalse(baseline.IsNew(finding));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that baseline entropy round-trips through Gitleaks float precision.
    /// </summary>
    [TestMethod]
    public void LoadRoundsEntropyThroughGitleaksFloatPrecision()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"), "baseline.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            Finding finding = CreateFinding(match: "token-12345", secret: "token-12345", entropy: 3.4594316482543945);
            File.WriteAllText(path, GitleaksJsonReportWriter.Write([finding]));

            GitleaksBaseline baseline = GitleaksBaseline.Load(path);

            Assert.IsFalse(baseline.IsNew(finding));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that non-JSON baseline files are rejected.
    /// </summary>
    [TestMethod]
    public void LoadRejectsUnsupportedFormat()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"), "baseline.csv");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            File.WriteAllText(path, "RuleID,File");

            InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksBaseline.Load(path));

            Assert.Contains("the format of the file", exception.Message);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    private static Finding CreateFinding(
        string match = "token=secret",
        string secret = "secret",
        string fingerprint = "fingerprint",
        IReadOnlyList<string>? tags = null,
        double entropy = 3.25)
    {
        return new Finding(
            "rule",
            "description",
            1,
            1,
            2,
            13,
            match,
            secret,
            "secrets.txt",
            string.Empty,
            "commit",
            entropy,
            "author",
            "author@example.com",
            "2026-07-05T00:00:00Z",
            "message",
            tags ?? [],
            fingerprint);
    }
}
