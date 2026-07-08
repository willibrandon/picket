using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="RuleSet" />.
/// </summary>
[TestClass]
public sealed class RuleSetTests
{
    /// <summary>
    /// Verifies that programmatic rule sets cannot exceed the scanner rule-count boundary.
    /// </summary>
    [TestMethod]
    public void ConstructorRejectsExcessiveRuleCount()
    {
        var rules = new List<SecretRule>(RuleSet.MaxRuleCount + 1);
        for (int i = 0; i <= RuleSet.MaxRuleCount; i++)
        {
            rules.Add(SecretRule.Create($"rule-{i}", string.Empty, "token-[0-9]+"));
        }

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new RuleSet(rules));

        Assert.AreEqual("rules", exception.ParamName);
    }
}
