namespace Picket.Engine;

/// <summary>
/// Represents supporting evidence that satisfied a composite rule requirement.
/// </summary>
/// <param name="ruleID">The supporting rule identifier.</param>
/// <param name="startLine">The one-based source line.</param>
/// <param name="secret">The supporting secret text.</param>
public sealed class RequiredFinding(string ruleID, int startLine, string secret)
{
    /// <summary>
    /// Gets the supporting rule identifier.
    /// </summary>
    public string RuleID { get; } = ruleID;

    /// <summary>
    /// Gets the one-based source line.
    /// </summary>
    public int StartLine { get; } = startLine;

    /// <summary>
    /// Gets the supporting secret text.
    /// </summary>
    public string Secret { get; } = secret;
}
