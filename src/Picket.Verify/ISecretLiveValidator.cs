using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Defines a provider-specific live secret validator.
/// </summary>
public interface ISecretLiveValidator
{
    /// <summary>
    /// Gets the provider identifier used for cache keys and audit records.
    /// </summary>
    string Provider { get; }

    /// <summary>
    /// Gets the validator version or configuration fingerprint used for cache invalidation.
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Gets the provider endpoint contacted by this validator.
    /// </summary>
    Uri Endpoint { get; }

    /// <summary>
    /// Returns a value indicating whether this validator can verify the finding.
    /// </summary>
    /// <param name="finding">The finding to evaluate.</param>
    /// <returns><see langword="true" /> when the validator supports the finding; otherwise <see langword="false" />.</returns>
    bool Supports(Finding finding);

    /// <summary>
    /// Verifies the finding by contacting the provider.
    /// </summary>
    /// <param name="finding">The finding to verify.</param>
    /// <param name="cancellationToken">A token that can cancel the provider request.</param>
    /// <returns>The live validation result.</returns>
    ValueTask<SecretValidationResult> VerifyAsync(Finding finding, CancellationToken cancellationToken);
}
