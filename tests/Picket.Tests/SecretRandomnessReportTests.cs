using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Verifies native report coverage and compatibility isolation for randomness metadata.
/// </summary>
[TestClass]
public sealed class SecretRandomnessReportTests
{
    private const string RandomSample = "a8F2kL9mQ4xT7vN1zR6pW3cY";

    /// <summary>
    /// Verifies every lossless native report surface exposes calibrated score metadata.
    /// </summary>
    [TestMethod]
    public void NativeReportWritersExposeRandomnessMetadata()
    {
        Finding finding = CreateFinding();
        SecretRule rule = CreateRule();

        string json = PicketJsonReportWriter.Write([finding], [rule]);
        string jsonl = PicketJsonlReportWriter.Write([finding], [rule]);
        string csv = PicketCsvReportWriter.Write([finding], [rule]);
        string toon = PicketToonReportWriter.Write([finding], [rule]);
        string sarif = PicketSarifReportWriter.Write([finding], [rule]);
        string html = PicketHtmlReportWriter.Write([finding], [rule]);
        string junit = PicketJunitReportWriter.Write([finding], [rule]);

        Assert.Contains("\"randomness\":{\"model\":\"picket-random-v1\",\"score\":0.902542", json);
        Assert.Contains("\"randomnessThreshold\":0.8", json);
        Assert.Contains("\"randomness\":{\"model\":\"picket-random-v1\",\"score\":0.902542", jsonl);
        Assert.Contains("RandomnessModel,RandomnessScore,RandomnessClassification", csv);
        Assert.Contains("picket-random-v1,0.902542,likely-random", csv);
        Assert.Contains("randomnessModel,randomnessScore,randomnessClassification", toon);
        Assert.Contains("picket-random-v1,0.902542,likely-random", toon);
        Assert.Contains("\"randomness\": {", sarif);
        Assert.Contains("\"encodedTextSignal\": 0", sarif);
        Assert.Contains("Randomness Model", html);
        Assert.Contains("0.902542 (likely-random)", html);
        Assert.Contains("&#34;randomness&#34;:{", junit);
    }

    /// <summary>
    /// Verifies Gitleaks-compatible writers do not expose native randomness fields.
    /// </summary>
    [TestMethod]
    public void CompatibilityReportWritersOmitRandomnessMetadata()
    {
        Finding finding = CreateFinding();
        SecretRule rule = CreateRule();

        string json = GitleaksJsonReportWriter.Write([finding]);
        string csv = GitleaksCsvReportWriter.Write([finding]);
        string junit = GitleaksJunitReportWriter.Write([finding]);
        string sarif = GitleaksSarifReportWriter.Write([finding], [rule]);

        Assert.DoesNotContain("randomness", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("randomness", csv, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("randomness", junit, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("randomness", sarif, StringComparison.OrdinalIgnoreCase);
    }

    private static Finding CreateFinding()
    {
        return new Finding(
            "random-token",
            "Detected a random token.",
            1,
            1,
            5,
            28,
            RandomSample,
            RandomSample,
            "secret.txt",
            string.Empty,
            string.Empty,
            4.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["random"],
            "secret.txt:random-token:1",
            string.Concat("key=", RandomSample),
            randomness: SecretRandomnessScorer.Assess(RandomSample));
    }

    private static SecretRule CreateRule()
    {
        return SecretRule.Create(
            "random-token",
            "Detected a random token.",
            "key=([A-Za-z0-9]+)",
            secretGroup: 1,
            randomnessThreshold: SecretRandomnessScorer.LikelyRandomThreshold);
    }
}
