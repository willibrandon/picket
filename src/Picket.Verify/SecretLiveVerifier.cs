using Picket.Engine;
using Picket.Security;

namespace Picket.Verify;

/// <summary>
/// Orchestrates live secret verification with endpoint guarding and persistent result caching.
/// </summary>
/// <param name="validators">The provider-specific validators to evaluate in order.</param>
/// <param name="cache">The optional persistent validation cache.</param>
/// <param name="options">The live verification options.</param>
public sealed class SecretLiveVerifier(
    ISecretLiveValidator[] validators,
    SecretValidationCache? cache = null,
    SecretLiveVerifierOptions? options = null)
{
    private readonly SecretValidationCache? _cache = cache;
    private readonly SecretLiveVerifierOptions _options = options ?? SecretLiveVerifierOptions.CreateDefault();
    private readonly ISecretLiveValidator[] _validators = ValidateValidators(validators);

    /// <summary>
    /// Verifies a finding with the first provider validator that supports it.
    /// </summary>
    /// <param name="finding">The finding to verify.</param>
    /// <param name="cancellationToken">A token that can cancel the verification request.</param>
    /// <returns>The live validation result.</returns>
    public async ValueTask<SecretValidationResult> VerifyAsync(Finding finding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        cancellationToken.ThrowIfCancellationRequested();

        for (int i = 0; i < _validators.Length; i++)
        {
            ISecretLiveValidator validator = _validators[i];
            if (!validator.Supports(finding))
            {
                continue;
            }

            EndpointGuardResult endpointResult = EndpointGuard.Evaluate(validator.Endpoint, _options.EndpointGuardOptions);
            if (!endpointResult.IsAllowed)
            {
                return new SecretValidationResult(
                    SecretValidationState.Error,
                    string.Concat("endpoint blocked: ", endpointResult.BlockReason.ToString()));
            }

            SecretValidationCacheKey? cacheKey = null;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (_cache is not null)
            {
                cacheKey = SecretValidationCacheKey.FromFinding(validator.Provider, validator.Version, finding, validator.Endpoint);
                if (_cache.TryRead(cacheKey, now, out SecretValidationResult? cachedResult))
                {
                    return cachedResult;
                }
            }

            SecretValidationResult result = await validator.VerifyAsync(finding, cancellationToken).ConfigureAwait(false);
            if (cacheKey is not null && _options.TryGetCacheDuration(result.State, out TimeSpan duration))
            {
                _cache!.Write(cacheKey, result, now + duration);
            }

            return result;
        }

        return new SecretValidationResult(SecretValidationState.Skipped, "no live validator supports the finding");
    }

    private static ISecretLiveValidator[] ValidateValidators(ISecretLiveValidator[] validators)
    {
        ArgumentNullException.ThrowIfNull(validators);

        for (int i = 0; i < validators.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(validators[i]);
        }

        return validators;
    }
}
