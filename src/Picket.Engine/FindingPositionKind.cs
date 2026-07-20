namespace Picket.Engine;

/// <summary>
/// Identifies the coordinate system used by a finding's source positions.
/// </summary>
public enum FindingPositionKind
{
    /// <summary>
    /// Uses Gitleaks-compatible UTF-8 byte columns and inclusive end positions.
    /// </summary>
    GitleaksUtf8BytesInclusive,

    /// <summary>
    /// Uses Unicode code-point columns and exclusive end positions.
    /// </summary>
    UnicodeCodePointsExclusive,
}
