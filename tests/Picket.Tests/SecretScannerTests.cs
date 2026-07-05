using System.Text;
using Picket.Engine;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="SecretScanner" />.
/// </summary>
[TestClass]
public sealed class SecretScannerTests
{
    /// <summary>
    /// Verifies that the bootstrap scanner detects an AWS access key from byte input.
    /// </summary>
    [TestMethod]
    public void ScanFindsAwsAccessTokenInByteInput()
    {
        byte[] input = Encoding.UTF8.GetBytes("before\nAWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nafter\n");

        CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("aws-access-token", finding.RuleID);
        Assert.AreEqual("AKIA1234567890ABCDEF", finding.Secret);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual("stdin:aws-access-token:2", finding.Fingerprint);
    }

    /// <summary>
    /// Verifies that non-matching input returns no findings.
    /// </summary>
    [TestMethod]
    public void ScanReturnsEmptyWhenNoRuleMatches()
    {
        byte[] input = Encoding.UTF8.GetBytes("no secrets here");

        CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that a missing keyword prevents regex execution for keyword-scoped rules.
    /// </summary>
    [TestMethod]
    public void ScanSkipsRulesWhenKeywordsAreMissing()
    {
        byte[] input = Encoding.UTF8.GetBytes("secret-value");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "keyword-gated",
                "Keyword gated",
                "secret-[a-z]+",
                keywords: ["missing"]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that keyword matching is ASCII case-insensitive.
    /// </summary>
    [TestMethod]
    public void ScanMatchesKeywordsCaseInsensitively()
    {
        byte[] input = Encoding.UTF8.GetBytes("secret-value");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "keyword-gated",
                "Keyword gated",
                "secret-[a-z]+",
                keywords: ["SECRET"]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("keyword-gated", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies that rules without keywords still run.
    /// </summary>
    [TestMethod]
    public void ScanRunsRulesWithoutKeywords()
    {
        byte[] input = Encoding.UTF8.GetBytes("nokey-123");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "no-keyword",
                "No keyword",
                "nokey-[0-9]+"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("no-keyword", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies that entropy uses Gitleaks' strict greater-than threshold.
    /// </summary>
    [TestMethod]
    public void ScanSuppressesSecretsAtEntropyThreshold()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-abcdef12");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "entropy-gated",
                "Entropy gated",
                "token-([a-z0-9]+)",
                secretGroup: 1,
                entropy: 3),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that secrets above the configured entropy threshold are reported.
    /// </summary>
    [TestMethod]
    public void ScanReportsSecretsAboveEntropyThreshold()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-abcdef12");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "entropy-gated",
                "Entropy gated",
                "token-([a-z0-9]+)",
                secretGroup: 1,
                entropy: 2.9),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("abcdef12", findings[0].Secret);
        Assert.AreEqual(3, findings[0].Entropy);
    }
}
