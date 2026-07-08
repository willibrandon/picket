namespace Picket.Rules;

/// <summary>
/// Immutable collection of secret detection rules.
/// </summary>
/// <param name="rules">Rules in deterministic evaluation order.</param>
/// <param name="allowlists">Global allowlists used to suppress findings.</param>
/// <param name="regexesPrevalidated">A value indicating whether rule and allowlist regexes are already validated and can be compiled lazily.</param>
public sealed class RuleSet(
    IReadOnlyList<SecretRule> rules,
    IReadOnlyList<SecretAllowlist>? allowlists = null,
    bool regexesPrevalidated = false)
{
    /// <summary>
    /// Gets the maximum number of rules accepted in a single rule set.
    /// </summary>
    public const int MaxRuleCount = 10_000;

    /// <summary>
    /// Gets the rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = RequireRules(rules);

    /// <summary>
    /// Gets global allowlists used to suppress findings.
    /// </summary>
    public IReadOnlyList<SecretAllowlist> Allowlists { get; } = allowlists ?? [];

    /// <summary>
    /// Gets a value indicating whether rule and allowlist regexes are already validated and can be compiled lazily.
    /// </summary>
    public bool RegexesPrevalidated { get; } = regexesPrevalidated;

    private static IReadOnlyList<SecretRule> RequireRules(IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rules.Count, MaxRuleCount, nameof(rules));
        return rules;
    }
}
