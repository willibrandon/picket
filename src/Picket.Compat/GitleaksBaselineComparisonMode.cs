namespace Picket.Compat;

/// <summary>
/// Specifies how findings are compared with a Gitleaks baseline.
/// </summary>
public enum GitleaksBaselineComparisonMode
{
    /// <summary>
    /// Uses the exact field comparison implemented by Gitleaks.
    /// </summary>
    Exact,

    /// <summary>
    /// Treats LF and CRLF evidence as equivalent while preserving all other identity fields.
    /// </summary>
    PortableLineEndings,
}
