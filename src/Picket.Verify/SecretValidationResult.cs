namespace Picket.Verify;

/// <summary>
/// Represents the result of offline validation for one finding.
/// </summary>
/// <param name="state">The validation state.</param>
/// <param name="reason">A concise non-secret reason for the state.</param>
public sealed class SecretValidationResult(SecretValidationState state, string reason = "")
{
    /// <summary>
    /// Gets the validation state.
    /// </summary>
    public SecretValidationState State { get; } = state;

    /// <summary>
    /// Gets a concise non-secret reason for the state.
    /// </summary>
    public string Reason { get; } = reason ?? string.Empty;

    /// <summary>
    /// Gets the stable report value for the state.
    /// </summary>
    public string ReportValue => ToReportValue(State);

    /// <summary>
    /// Converts a validation state to its stable native report value.
    /// </summary>
    /// <param name="state">The validation state.</param>
    /// <returns>The stable native report value.</returns>
    public static string ToReportValue(SecretValidationState state)
    {
        return state switch
        {
            SecretValidationState.StructurallyValid => "structurally-valid",
            SecretValidationState.TestCredential => "test-credential",
            SecretValidationState.Invalid => "invalid",
            _ => "unknown",
        };
    }
}
