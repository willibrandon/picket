namespace Picket.Rules;

/// <summary>
/// Immutable collection of secret detection rules.
/// </summary>
/// <param name="rules">Rules in deterministic evaluation order.</param>
/// <param name="allowlists">Global allowlists used to suppress findings.</param>
public sealed class RuleSet(IReadOnlyList<SecretRule> rules, IReadOnlyList<SecretAllowlist>? allowlists = null)
{
    /// <summary>
    /// Gets the rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = rules ?? throw new ArgumentNullException(nameof(rules));

    /// <summary>
    /// Gets global allowlists used to suppress findings.
    /// </summary>
    public IReadOnlyList<SecretAllowlist> Allowlists { get; } = allowlists ?? [];
}
