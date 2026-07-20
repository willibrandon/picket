using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests native rule hardening derived from upstream false-positive reports.
/// </summary>
[TestClass]
public sealed class NativeRuleHardeningTests
{
    private const string SquareBase64LikeMimeSample =
        "mJeJ0b3bVQZu6P8AUEsHCFDBu3Q+EAAAWRAAAFBLAwQUAAgICAAYZxlbAAAAAAAAAAAAAAAAEwAA";
    private const string VueAttributeSample =
        "<my-custom-component v-model=\"anyValWithKeyInside\" :followed-by-a-dynamic-attributes-with-at-least-two-dashes=\"true\" />";

    /// <summary>
    /// Verifies native randomness filtering rejects a base64-like MIME fragment matched by the Square rule.
    /// </summary>
    [TestMethod]
    public void NativeSquareRuleRejectsBase64LikeMimeFragment()
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("square-access-token", SquareBase64LikeMimeSample);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("square-access-token", SquareBase64LikeMimeSample);

        Assert.IsNotEmpty(strictFindings);
        Assert.IsEmpty(nativeFindings);
    }

    /// <summary>
    /// Verifies current strict and native generic rules reject the reported Vue attribute false positive.
    /// </summary>
    [TestMethod]
    public void GenericRulesRejectVueAttributeName()
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", VueAttributeSample);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("generic-api-key", VueAttributeSample);

        Assert.IsEmpty(strictFindings);
        Assert.IsEmpty(nativeFindings);
    }

    /// <summary>
    /// Verifies the native generic rule covers modern assignment forms without changing strict compatibility.
    /// </summary>
    /// <param name="input">The source text to scan.</param>
    [TestMethod]
    [DataRow("secret                         = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    [DataRow("my_secret: str = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    [DataRow("my_secret: SecretStr = SecretStr(\"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\")")]
    [DataRow("pword = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    public void NativeGenericRuleCoversModernAssignments(string input)
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", input);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("generic-api-key", input);

        Assert.IsEmpty(strictFindings);
        Assert.HasCount(1, nativeFindings);
        Assert.AreEqual("A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH", nativeFindings[0].Secret);
    }

    private static IReadOnlyList<Finding> ScanNativeRule(string ruleId, string input)
    {
        SecretRule rule = PicketConfigLoader.LoadDefaultRuleSet().Rules.Single(
            rule => rule.Id.Equals(ruleId, StringComparison.Ordinal));
        return Scan(rule, input, enableRandomnessScoring: true);
    }

    private static IReadOnlyList<Finding> ScanStrictRule(string ruleId, string input)
    {
        SecretRule rule = GitleaksConfigLoader.LoadDefaultRuleSet().Rules.Single(
            rule => rule.Id.Equals(ruleId, StringComparison.Ordinal));
        return Scan(rule, input, enableRandomnessScoring: false);
    }

    private static IReadOnlyList<Finding> Scan(
        SecretRule rule,
        string input,
        bool enableRandomnessScoring)
    {
        return SecretScanner.Scan(new ScanRequest(
            Encoding.UTF8.GetBytes(input),
            "fixture.txt",
            new RuleSet([rule]),
            maxDecodeDepth: 0)
        {
            EnableRandomnessScoring = enableRandomnessScoring,
        });
    }
}
