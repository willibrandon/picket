using Hex1b.Theming;

namespace Picket.Tui;

/// <summary>
/// Maps scanner metadata values to the TUI's semantic colors.
/// </summary>
internal static class PicketTuiSemanticColors
{
    /// <summary>
    /// Gets the semantic color for a finding severity.
    /// </summary>
    /// <param name="severity">The finding severity.</param>
    /// <returns>The matching semantic color.</returns>
    internal static Hex1bColor GetSeverity(string severity)
    {
        if (severity.Equals("critical", StringComparison.OrdinalIgnoreCase))
        {
            return PicketTuiPalette.ErrorForeground;
        }

        if (severity.Equals("high", StringComparison.OrdinalIgnoreCase)
            || severity.Equals("medium", StringComparison.OrdinalIgnoreCase))
        {
            return PicketTuiPalette.WarningForeground;
        }

        return severity.Equals("low", StringComparison.OrdinalIgnoreCase)
            || severity.Equals("info", StringComparison.OrdinalIgnoreCase)
            || severity.Equals("informational", StringComparison.OrdinalIgnoreCase)
                ? PicketTuiPalette.InfoForeground
                : PicketTuiPalette.MutedForeground;
    }

    /// <summary>
    /// Gets the semantic color for a finding validation state.
    /// </summary>
    /// <param name="validationState">The validation state.</param>
    /// <returns>The matching semantic color.</returns>
    internal static Hex1bColor GetValidation(string validationState)
    {
        if (validationState.Equals("active", StringComparison.OrdinalIgnoreCase))
        {
            return PicketTuiPalette.ErrorForeground;
        }

        if (validationState.Equals("inactive", StringComparison.OrdinalIgnoreCase))
        {
            return PicketTuiPalette.SuccessForeground;
        }

        if (validationState.Equals("error", StringComparison.OrdinalIgnoreCase)
            || validationState.Equals("test-credential", StringComparison.OrdinalIgnoreCase))
        {
            return PicketTuiPalette.WarningForeground;
        }

        return validationState.Equals("structurally-valid", StringComparison.OrdinalIgnoreCase)
            ? PicketTuiPalette.InfoForeground
            : PicketTuiPalette.MutedForeground;
    }
}
