using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="SecretRandomnessScorer" /> and native score filtering.
/// </summary>
[TestClass]
public sealed class SecretRandomnessScorerTests
{
    private const string EncodedTextSample = "Y29uZmlndXJhdGlvbi1wYXNzd29yZC1wbGFjZWhvbGRlcg==";
    private const string PrefixedRandomSample = "prefix_key_a8F2kL9mQ4xT7vN1zR6pW3cY5uH0jK8sD2qP9bX4nM7wE1tL6rV3cZ0gF5hJ2";
    private const string RandomSample = "a8F2kL9mQ4xT7vN1zR6pW3cY";
    private const string StructuredSample = "password1234567890";

    /// <summary>
    /// Verifies calibrated random and structured fixtures remain on opposite stable thresholds.
    /// </summary>
    [TestMethod]
    public void AssessClassifiesCalibratedFixtures()
    {
        SecretRandomnessAssessment random = SecretRandomnessScorer.Assess(RandomSample);
        SecretRandomnessAssessment structured = SecretRandomnessScorer.Assess(StructuredSample);

        Assert.AreEqual(SecretRandomnessScorer.ModelVersion, random.Model);
        Assert.AreEqual(0.902542, random.Score);
        Assert.AreEqual("likely-random", random.Classification);
        Assert.AreEqual(0.066778, structured.Score);
        Assert.AreEqual("likely-structured", structured.Classification);
        Assert.Contains("placeholder-marker", structured.Signals);
        for (int i = 0; i < 32; i++)
        {
            Assert.AreEqual(random.Score, SecretRandomnessScorer.Assess(RandomSample).Score);
            Assert.AreEqual(structured.Score, SecretRandomnessScorer.Assess(StructuredSample).Score);
        }
    }

    /// <summary>
    /// Verifies bounded Base64 inspection distinguishes encoded human text from generated tokens.
    /// </summary>
    [TestMethod]
    public void AssessRecognizesEncodedPrintableText()
    {
        SecretRandomnessAssessment assessment = SecretRandomnessScorer.Assess(EncodedTextSample);

        Assert.AreEqual(0.188818, assessment.Score);
        Assert.AreEqual(1, assessment.Features.EncodedTextSignal);
        Assert.Contains("encoded-printable-text", assessment.Signals);
    }

    /// <summary>
    /// Verifies provider-style prefixes do not hide the token payload from feature extraction.
    /// </summary>
    [TestMethod]
    public void ExtractFeaturesSelectsLongestTokenSegment()
    {
        SecretRandomnessAssessment assessment = SecretRandomnessScorer.Assess(PrefixedRandomSample);

        Assert.AreEqual(11, assessment.Features.SampleOffset);
        Assert.AreEqual(61, assessment.Features.SampleLength);
        Assert.AreEqual("likely-random", assessment.Classification);
    }

    /// <summary>
    /// Verifies feature extraction remains bounded for arbitrarily long candidate values.
    /// </summary>
    [TestMethod]
    public void ExtractFeaturesBoundsLongCandidateValues()
    {
        string value = string.Concat(new string('A', 4096), new string('9', 4096));

        SecretRandomnessAssessment assessment = SecretRandomnessScorer.Assess(value);
        SecretRandomnessFeatures features = assessment.Features;

        Assert.AreEqual(0, features.SampleOffset);
        Assert.AreEqual(512, features.SampleLength);
        Assert.AreEqual("hex", features.Alphabet);
    }

    /// <summary>
    /// Verifies strict scans do not calculate native randomness metadata.
    /// </summary>
    [TestMethod]
    public void ScanDoesNotScoreCompatibilityRequests()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: 0);
        byte[] input = Encoding.UTF8.GetBytes(string.Concat("key=", RandomSample));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, maxDecodeDepth: 0));

        Assert.HasCount(1, findings);
        Assert.IsNull(findings[0].Randomness);
    }

    /// <summary>
    /// Verifies native scans attach score metadata without suppressing rules that have no threshold.
    /// </summary>
    [TestMethod]
    public void ScanScoresNativeRequests()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: 0);
        byte[] input = Encoding.UTF8.GetBytes(string.Concat("key=", StructuredSample));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            input,
            "secret.txt",
            rules,
            maxDecodeDepth: 0)
        {
            EnableRandomnessScoring = true,
        });

        Assert.HasCount(1, findings);
        SecretRandomnessAssessment assessment = findings[0].Randomness
            ?? throw new InvalidOperationException("Native finding did not include randomness metadata.");
        Assert.AreEqual("likely-structured", assessment.Classification);
    }

    /// <summary>
    /// Verifies native scans score the matched bytes before report text replaces invalid UTF-8.
    /// </summary>
    [TestMethod]
    public void ScanScoresMatchedBytesBeforeReportDecoding()
    {
        byte[] input =
        [
            (byte)'k',
            (byte)'e',
            (byte)'y',
            (byte)'=',
            0x80,
            0x81,
            0x82,
            0x83,
            0x84,
            0x85,
            0x86,
            0x87,
        ];
        SecretRule rule = SecretRule.Create("byte-token", "Byte token", "key=((?-u:.){8})", secretGroup: 1);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.bin", rules)
        {
            EnableRandomnessScoring = true,
        });

        Assert.HasCount(1, findings);
        SecretRandomnessAssessment expected = SecretRandomnessScorer.Assess(input.AsSpan(4));
        Assert.AreEqual(expected.Score, findings[0].Randomness?.Score);
        Assert.AreNotEqual(SecretRandomnessScorer.Assess(findings[0].Secret).Score, findings[0].Randomness?.Score);
    }

    /// <summary>
    /// Verifies explicit native rule thresholds suppress structured values and retain random values.
    /// </summary>
    [TestMethod]
    public void ScanAppliesExplicitRandomnessThreshold()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: SecretRandomnessScorer.LikelyRandomThreshold);
        byte[] structuredInput = Encoding.UTF8.GetBytes(string.Concat("key=", StructuredSample));
        byte[] randomInput = Encoding.UTF8.GetBytes(string.Concat("key=", RandomSample));

        IReadOnlyList<Finding> structuredFindings = SecretScanner.Scan(new ScanRequest(
            structuredInput,
            "structured.txt",
            rules,
            maxDecodeDepth: 0)
        {
            EnableRandomnessScoring = true,
        });
        IReadOnlyList<Finding> randomFindings = SecretScanner.Scan(new ScanRequest(
            randomInput,
            "random.txt",
            rules,
            maxDecodeDepth: 0)
        {
            EnableRandomnessScoring = true,
        });

        Assert.IsEmpty(structuredFindings);
        Assert.HasCount(1, randomFindings);
        SecretRandomnessAssessment assessment = randomFindings[0].Randomness
            ?? throw new InvalidOperationException("Native finding did not include randomness metadata.");
        Assert.IsGreaterThanOrEqualTo(SecretRandomnessScorer.LikelyRandomThreshold, assessment.Score);
    }

    /// <summary>
    /// Verifies a finding is retained when its score equals the rule threshold exactly.
    /// </summary>
    [TestMethod]
    public void ScanRetainsScoreEqualToExplicitThreshold()
    {
        double score = SecretRandomnessScorer.Assess(RandomSample).Score;
        CompiledRuleSet rules = CreateRules(randomnessThreshold: score);
        byte[] input = Encoding.UTF8.GetBytes(string.Concat("key=", RandomSample));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            input,
            "secret.txt",
            rules,
            maxDecodeDepth: 0)
        {
            EnableRandomnessScoring = true,
        });

        Assert.HasCount(1, findings);
        Assert.AreEqual(score, findings[0].Randomness?.Score);
    }

    /// <summary>
    /// Verifies an ellipsis inside raw secret material is not mistaken for a redaction marker.
    /// </summary>
    [TestMethod]
    public void ApplyScoresRawEvidenceContainingEllipsis()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: 0);
        string secret = string.Concat(RandomSample, "...", RandomSample);

        List<Finding> findings = SecretRandomnessFindingProcessor.Apply(
            [CreateFinding(secret, assessment: null)],
            rules);

        Assert.HasCount(1, findings);
        Assert.AreEqual(SecretRandomnessScorer.ModelVersion, findings[0].Randomness?.Model);
    }

    /// <summary>
    /// Verifies report input with raw evidence is rescored when its model identifier is stale.
    /// </summary>
    [TestMethod]
    public void ApplyReplacesStaleAssessmentWhenEvidenceIsAvailable()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: 0);
        SecretRandomnessAssessment current = SecretRandomnessScorer.Assess(RandomSample);
        SecretRandomnessAssessment stale = SecretRandomnessAssessment.Create(
            "picket-random-old",
            0,
            "likely-structured",
            current.Features,
            current.Signals);

        List<Finding> findings = SecretRandomnessFindingProcessor.Apply(
            [CreateFinding(RandomSample, stale)],
            rules);

        Assert.HasCount(1, findings);
        Assert.AreEqual(SecretRandomnessScorer.ModelVersion, findings[0].Randomness?.Model);
        Assert.AreEqual(current.Score, findings[0].Randomness?.Score);
    }

    /// <summary>
    /// Verifies stale assessments without raw evidence cannot suppress a finding.
    /// </summary>
    [TestMethod]
    public void ApplyDoesNotUseStaleAssessmentToSuppressRedactedFinding()
    {
        CompiledRuleSet rules = CreateRules(randomnessThreshold: SecretRandomnessScorer.LikelyRandomThreshold);
        SecretRandomnessAssessment current = SecretRandomnessScorer.Assess(RandomSample);
        SecretRandomnessAssessment stale = SecretRandomnessAssessment.Create(
            "picket-random-old",
            0,
            "likely-structured",
            current.Features,
            current.Signals);

        List<Finding> findings = SecretRandomnessFindingProcessor.Apply(
            [CreateFinding("REDACTED", stale)],
            rules);

        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-random-old", findings[0].Randomness?.Model);
    }

    private static CompiledRuleSet CreateRules(double randomnessThreshold)
    {
        SecretRule rule = SecretRule.Create(
            "random-token",
            "Random token",
            "key=([A-Za-z0-9]+)",
            secretGroup: 1,
            randomnessThreshold: randomnessThreshold);
        return CompiledRuleSet.Compile(new RuleSet([rule]));
    }

    private static Finding CreateFinding(string secret, SecretRandomnessAssessment? assessment)
    {
        return new Finding(
            "random-token",
            "Random token",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:random-token:1",
            secret,
            randomness: assessment);
    }
}
