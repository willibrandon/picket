namespace Picket.Verify;

/// <summary>
/// Represents exhaustion of a live-validation request budget.
/// </summary>
internal sealed class SecretLiveRequestBudgetExceededException(bool providerBudget)
    : Exception(providerBudget
        ? "live verification request budget exhausted for provider"
        : "live verification request budget exhausted")
{
    /// <summary>
    /// Gets a value indicating whether the provider-specific budget was exhausted.
    /// </summary>
    internal bool IsProviderBudget { get; } = providerBudget;
}
