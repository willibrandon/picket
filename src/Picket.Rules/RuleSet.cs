namespace Picket.Rules;

/// <summary>
/// Immutable collection of secret detection rules.
/// </summary>
/// <param name="rules">Rules in deterministic evaluation order.</param>
public sealed class RuleSet(IReadOnlyList<SecretRule> rules)
{
    /// <summary>
    /// Gets the rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = rules ?? throw new ArgumentNullException(nameof(rules));
}
