using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using Picket.Verify;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests the provider rules in the embedded native default pack.
/// </summary>
[TestClass]
public sealed class NativeProviderRuleTests
{
    /// <summary>
    /// Verifies that every modern provider rule accepts its positive examples and rejects its negative examples.
    /// </summary>
    /// <param name="ruleId">The embedded native rule identifier.</param>
    [TestMethod]
    [DataRow("picket-anthropic-oauth-access-token")]
    [DataRow("picket-anthropic-oauth-refresh-token")]
    [DataRow("picket-claude-code-session-url")]
    [DataRow("picket-docker-registry-auth")]
    [DataRow("picket-groq-api-key")]
    [DataRow("picket-jwk-private-key")]
    [DataRow("picket-kubernetes-secret")]
    [DataRow("picket-mcp-server-credential")]
    [DataRow("picket-npm-auth-token")]
    [DataRow("picket-npm-basic-auth")]
    [DataRow("picket-openai-api-key")]
    [DataRow("picket-openai-codex-access-token")]
    [DataRow("picket-openai-codex-refresh-token")]
    [DataRow("picket-xai-api-key")]
    public void EmbeddedProviderRuleExamplesAreValid(string ruleId)
    {
        SecretRule rule = GetNativeRule(ruleId);

        for (int i = 0; i < rule.Examples.Count; i++)
        {
            IReadOnlyList<Finding> findings = Scan(rule, rule.Examples[i]);
            Assert.Contains(
                finding => finding.RuleID.Equals(ruleId, StringComparison.Ordinal),
                findings,
                $"Positive example {i + 1} did not match {ruleId}.");
            SecretValidationResult validation = OfflineSecretValidator.Validate(findings[0]);
            Assert.AreEqual(
                SecretValidationState.StructurallyValid,
                validation.State,
                $"Positive example {i + 1} did not validate for {ruleId}: {validation.Reason}");
        }

        for (int i = 0; i < rule.NegativeExamples.Count; i++)
        {
            IReadOnlyList<Finding> findings = Scan(rule, rule.NegativeExamples[i]);
            Assert.DoesNotContain(
                finding => finding.RuleID.Equals(ruleId, StringComparison.Ordinal),
                findings,
                $"Negative example {i + 1} matched {ruleId}.");
        }
    }

    /// <summary>
    /// Verifies that the native Google API key rule accepts a key before another URL query parameter.
    /// </summary>
    [TestMethod]
    public void GoogleApiKeyRuleAcceptsUrlQueryDelimiter()
    {
        SecretRule rule = GetNativeRule("picket-google-api-key");
        string apiKey = rule.Examples[0].Split('"')[1];
        string input = $"https://chat.googleapis.com/v1/spaces/example/messages?key={apiKey}&token=placeholder";

        IReadOnlyList<Finding> findings = Scan(rule, input);

        Assert.HasCount(1, findings);
        Assert.AreEqual(apiKey, findings[0].Secret);
    }

    /// <summary>
    /// Verifies that the native GitHub App rule accepts both classic and stateless installation token formats.
    /// </summary>
    [TestMethod]
    public void GitHubAppRuleAcceptsClassicAndStatelessFormats()
    {
        SecretRule rule = GetNativeRule("picket-github-app-token");

        IReadOnlyList<Finding> classicFindings = Scan(rule, rule.Examples[0]);
        IReadOnlyList<Finding> statelessFindings = Scan(rule, rule.Examples[1]);

        Assert.HasCount(1, classicFindings);
        Assert.HasCount(1, statelessFindings);
    }

    /// <summary>
    /// Verifies that modern native rules do not alter the strict Gitleaks rule set.
    /// </summary>
    [TestMethod]
    public void GitleaksDefaultRuleSetExcludesNativeProviderRules()
    {
        RuleSet strictRules = GitleaksConfigLoader.LoadDefaultRuleSet();

        Assert.DoesNotContain(
            static rule => rule.Id.StartsWith("picket-", StringComparison.Ordinal),
            strictRules.Rules);
        Assert.Contains(
            static rule => rule.Id.Equals("openai-api-key", StringComparison.Ordinal),
            strictRules.Rules);
        Assert.Contains(
            static rule => rule.Id.Equals("kubernetes-secret-yaml", StringComparison.Ordinal),
            strictRules.Rules);
    }

    private static SecretRule GetNativeRule(string ruleId)
    {
        return PicketConfigLoader.LoadDefaultRuleSet().Rules.Single(
            rule => rule.Id.Equals(ruleId, StringComparison.Ordinal));
    }

    private static IReadOnlyList<Finding> Scan(SecretRule rule, string input)
    {
        return SecretScanner.Scan(new ScanRequest(
            Encoding.UTF8.GetBytes(input),
            "fixture.txt",
            new RuleSet([rule]),
            maxDecodeDepth: 0)
        {
            EnableNativeDetectors = true,
            PositionKind = FindingPositionKind.UnicodeCodePointsExclusive,
        });
    }
}
