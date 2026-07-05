using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

/// <summary>
/// Represents a rule set with precompiled Scout regexes and keyword prefilters.
/// </summary>
/// <param name="rules">The source rules in deterministic evaluation order.</param>
public sealed class CompiledRuleSet(RuleSet rules)
{
    /// <summary>
    /// Gets the source rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = RequireRules(rules).Rules;

    internal List<CompiledRule> CompiledRules { get; } = CompileRules(rules);

    internal List<CompiledAllowlist> Allowlists { get; } = CompiledAllowlist.Compile(rules.Allowlists);

    /// <summary>
    /// Compiles a source rule set.
    /// </summary>
    /// <param name="rules">The source rules in deterministic evaluation order.</param>
    /// <returns>The compiled rule set.</returns>
    public static CompiledRuleSet Compile(RuleSet rules)
    {
        return new CompiledRuleSet(rules);
    }

    private static RuleSet RequireRules(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return rules;
    }

    private static List<CompiledRule> CompileRules(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var compiledRules = new List<CompiledRule>(rules.Rules.Count);
        foreach (SecretRule rule in rules.Rules)
        {
            compiledRules.Add(new CompiledRule(
                rule,
                CompileOptionalRegex(rule.Pattern),
                CompileOptionalRegex(rule.PathPattern),
                CompiledAllowlist.Compile(rule.Allowlists),
                KeywordPrefilter.Create(rule.Keywords)));
        }

        return compiledRules;
    }

    private static ByteRegex? CompileOptionalRegex(string pattern)
    {
        return pattern.Length == 0 ? null : ByteRegex.Compile(pattern);
    }
}
