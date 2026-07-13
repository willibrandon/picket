namespace Picket.Rules;

/// <summary>
/// Provides stable identifiers for the built-in Picket rule packs.
/// </summary>
public static class PicketRulePackNames
{
    /// <summary>
    /// Identifies the pinned Gitleaks-compatible rule pack.
    /// </summary>
    public const string Gitleaks = "gitleaks";

    /// <summary>
    /// Identifies Picket's high-confidence native default rule pack.
    /// </summary>
    public const string Default = "picket-default";

    /// <summary>
    /// Identifies Picket's opt-in rule pack for broader, more aggressive detection.
    /// </summary>
    public const string Strict = "picket-strict";

    /// <summary>
    /// Identifies Picket's opt-in rule pack for detectors that are still being tuned.
    /// </summary>
    public const string Experimental = "picket-experimental";
}
