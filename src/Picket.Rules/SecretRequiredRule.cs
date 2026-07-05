namespace Picket.Rules;

/// <summary>
/// Describes a Gitleaks-compatible supporting rule required by a primary rule.
/// </summary>
/// <param name="id">The required rule identifier.</param>
/// <param name="withinLines">The maximum line distance from the primary finding, or <see langword="null" /> for no line constraint.</param>
/// <param name="withinColumns">The maximum column distance from the primary finding, or <see langword="null" /> for no column constraint.</param>
public sealed class SecretRequiredRule(string id, int? withinLines = null, int? withinColumns = null)
{
    /// <summary>
    /// Gets the required rule identifier.
    /// </summary>
    public string Id { get; } = RequireText(id);

    /// <summary>
    /// Gets the maximum line distance from the primary finding, or <see langword="null" /> for no line constraint.
    /// </summary>
    public int? WithinLines { get; } = RequireNonNegative(withinLines);

    /// <summary>
    /// Gets the maximum column distance from the primary finding, or <see langword="null" /> for no column constraint.
    /// </summary>
    public int? WithinColumns { get; } = RequireNonNegative(withinColumns);

    private static string RequireText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int? RequireNonNegative(int? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }
}
