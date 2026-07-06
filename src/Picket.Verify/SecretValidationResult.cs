namespace Picket.Verify;

/// <summary>
/// Represents the result of validation for one finding.
/// </summary>
/// <param name="state">The validation state.</param>
/// <param name="reason">A concise non-secret reason for the state.</param>
/// <param name="identity">The non-secret identity discovered by live validation, or an empty string.</param>
/// <param name="scopes">The non-secret scopes discovered by live validation.</param>
/// <param name="reachableResources">The non-secret resources discovered by live validation.</param>
/// <param name="evidence">Non-secret evidence produced by validation.</param>
/// <param name="isPersistentCacheable">A value indicating whether the result can be written to the persistent validation cache.</param>
public sealed class SecretValidationResult(
    SecretValidationState state,
    string reason = "",
    string identity = "",
    string[]? scopes = null,
    string[]? reachableResources = null,
    string[]? evidence = null,
    bool isPersistentCacheable = true)
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
    /// Gets the non-secret identity discovered by live validation, or an empty string.
    /// </summary>
    public string Identity { get; } = identity ?? string.Empty;

    /// <summary>
    /// Gets the non-secret scopes discovered by live validation.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; } = CopyOrEmpty(scopes);

    /// <summary>
    /// Gets the non-secret resources discovered by live validation.
    /// </summary>
    public IReadOnlyList<string> ReachableResources { get; } = CopyOrEmpty(reachableResources);

    /// <summary>
    /// Gets non-secret evidence produced by validation.
    /// </summary>
    public IReadOnlyList<string> Evidence { get; } = CopyOrEmpty(evidence);

    /// <summary>
    /// Gets a value indicating whether the result can be written to the persistent validation cache.
    /// </summary>
    public bool IsPersistentCacheable { get; } = isPersistentCacheable;

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
            SecretValidationState.Active => "active",
            SecretValidationState.Inactive => "inactive",
            SecretValidationState.Skipped => "skipped",
            SecretValidationState.Error => "error",
            _ => "unknown",
        };
    }

    private static string[] CopyOrEmpty(string[]? values)
    {
        if (values is null || values.Length == 0)
        {
            return [];
        }

        var copy = new string[values.Length];
        Array.Copy(values, copy, values.Length);
        return copy;
    }
}
