namespace Picket.Rules;

/// <summary>
/// Describes how checks inside a secret allowlist are combined.
/// </summary>
public enum AllowlistCondition
{
    /// <summary>
    /// Allows a finding when any configured check matches.
    /// </summary>
    Or,

    /// <summary>
    /// Allows a finding only when every configured check matches.
    /// </summary>
    And,
}
