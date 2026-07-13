using Picket.Compat;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests Picket-native built-in rule-pack loading and layering.
/// </summary>
[TestClass]
public sealed class PicketConfigLoaderTests
{
    /// <summary>
    /// Verifies that opt-in rule packs do not affect the native default rule set.
    /// </summary>
    [TestMethod]
    public void LoadDefaultRuleSetExcludesOptInRulePacks()
    {
        RuleSet ruleSet = PicketConfigLoader.LoadDefaultRuleSet();
        string[] rulePacks = [.. ruleSet.Rules.Select(static rule => rule.RulePack)];

        Assert.DoesNotContain(PicketRulePackNames.Strict, rulePacks);
        Assert.DoesNotContain(PicketRulePackNames.Experimental, rulePacks);
    }

    /// <summary>
    /// Verifies that each built-in rule pack can be loaded independently.
    /// </summary>
    [TestMethod]
    public void LoadBuiltInRulePackReturnsOnlyRequestedRules()
    {
        RuleSet strict = PicketConfigLoader.LoadBuiltInRulePack(PicketRulePackNames.Strict);
        RuleSet experimental = PicketConfigLoader.LoadBuiltInRulePack(PicketRulePackNames.Experimental);
        string[] strictRulePacks = [.. strict.Rules.Select(static rule => rule.RulePack)];
        string[] experimentalRulePacks = [.. experimental.Rules.Select(static rule => rule.RulePack)];

        Assert.HasCount(3, strict.Rules);
        Assert.IsTrue(strictRulePacks.All(static rulePack => rulePack == PicketRulePackNames.Strict));
        Assert.AreEqual(1, strict.Rules.Single(static rule => rule.Id == "picket-strict-connection-string-password").SecretGroup);
        Assert.HasCount(2, experimental.Rules);
        Assert.IsTrue(experimentalRulePacks.All(static rulePack => rulePack == PicketRulePackNames.Experimental));
    }

    /// <summary>
    /// Verifies that repeated built-in selections layer over an explicitly resolved config.
    /// </summary>
    [TestMethod]
    public void LoadRuleSetLayersSelectedBuiltInRulePacks()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "picket.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "local-rule"
            regex = '''local-[0-9]+'''
            """);

        RuleSet ruleSet = PicketConfigLoader.LoadRuleSet(
            configPath,
            root.Path,
            PicketRulePackNames.Strict,
            PicketRulePackNames.Experimental);
        string[] ruleIds = [.. ruleSet.Rules.Select(static rule => rule.Id)];

        Assert.HasCount(6, ruleSet.Rules);
        Assert.Contains("local-rule", ruleIds);
        Assert.HasCount(3, ruleSet.Rules.Where(static rule => rule.RulePack == PicketRulePackNames.Strict).ToArray());
        Assert.HasCount(2, ruleSet.Rules.Where(static rule => rule.RulePack == PicketRulePackNames.Experimental).ToArray());
    }

    /// <summary>
    /// Verifies that unknown built-in rule-pack identifiers fail closed.
    /// </summary>
    [TestMethod]
    public void LoadBuiltInRulePackRejectsUnknownIdentifier()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PicketConfigLoader.LoadBuiltInRulePack("unknown"));

        Assert.Contains("unsupported built-in rule pack: unknown", exception.Message);
    }
}
