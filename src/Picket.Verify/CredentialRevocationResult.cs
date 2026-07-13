namespace Picket.Verify;

/// <summary>
/// Represents the non-secret result of an explicit credential revocation request.
/// </summary>
/// <param name="state">The revocation outcome.</param>
/// <param name="reason">A non-secret explanation of the outcome.</param>
/// <param name="credentialCount">The number of credentials in the request.</param>
/// <param name="httpStatusCode">The provider HTTP status code, when a response was received.</param>
public sealed class CredentialRevocationResult(
    CredentialRevocationState state,
    string reason,
    int credentialCount,
    int? httpStatusCode = null)
{
    /// <summary>
    /// Gets the revocation outcome.
    /// </summary>
    public CredentialRevocationState State { get; } = Enum.IsDefined(state)
        ? state
        : throw new ArgumentOutOfRangeException(nameof(state));

    /// <summary>
    /// Gets a non-secret explanation of the outcome.
    /// </summary>
    public string Reason { get; } = reason ?? throw new ArgumentNullException(nameof(reason));

    /// <summary>
    /// Gets the number of credentials in the request.
    /// </summary>
    public int CredentialCount { get; } = credentialCount >= 0
        ? credentialCount
        : throw new ArgumentOutOfRangeException(nameof(credentialCount));

    /// <summary>
    /// Gets the provider HTTP status code, when a response was received.
    /// </summary>
    public int? HttpStatusCode { get; } = httpStatusCode;
}
