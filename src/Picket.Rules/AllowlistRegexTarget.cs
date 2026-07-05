namespace Picket.Rules;

/// <summary>
/// Describes the finding field tested by allowlist regexes.
/// </summary>
public enum AllowlistRegexTarget
{
    /// <summary>
    /// Tests the captured secret value.
    /// </summary>
    Secret,

    /// <summary>
    /// Tests the full regex match.
    /// </summary>
    Match,

    /// <summary>
    /// Tests the full source line containing the finding.
    /// </summary>
    Line,
}
