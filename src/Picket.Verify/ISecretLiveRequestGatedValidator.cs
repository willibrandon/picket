using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Defines a validator that applies shared policy to each outbound request.
/// </summary>
internal interface ISecretLiveRequestGatedValidator
{
    /// <summary>
    /// Verifies a finding through the supplied request gate.
    /// </summary>
    /// <param name="finding">The finding to verify.</param>
    /// <param name="requestGate">The gate for each outbound provider request.</param>
    /// <param name="cancellationToken">A token that can cancel verification.</param>
    /// <returns>The live validation result.</returns>
    ValueTask<SecretValidationResult> VerifyAsync(
        Finding finding,
        ISecretLiveRequestGate requestGate,
        CancellationToken cancellationToken);
}
