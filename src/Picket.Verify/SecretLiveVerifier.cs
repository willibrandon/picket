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
    SecretLiveVerifierOptions? options = null) : IDisposable
{
    private readonly SecretValidationCache? _cache = cache;
    private readonly SecretLiveVerifierOptions _options = options ?? SecretLiveVerifierOptions.CreateDefault();
    private readonly Dictionary<string, SecretValidationResult> _requestCache = new(StringComparer.Ordinal);
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

            DateTimeOffset now = DateTimeOffset.UtcNow;
            SecretValidationCacheKey cacheKey = SecretValidationCacheKey.FromFinding(validator.Provider, validator.Version, finding, validator.Endpoint);
            if (_requestCache.TryGetValue(cacheKey.Fingerprint, out SecretValidationResult? requestCachedResult))
            {
                return requestCachedResult;
            }

            if (_cache is not null)
            {
                if (_cache.TryRead(cacheKey, now, out SecretValidationResult? cachedResult))
                {
                    _requestCache[cacheKey.Fingerprint] = cachedResult;
                    return cachedResult;
                }
            }

            SecretValidationResult result = await validator.VerifyAsync(finding, cancellationToken).ConfigureAwait(false);
            _requestCache[cacheKey.Fingerprint] = result;
            if (_cache is not null && _options.TryGetCacheDuration(result.State, out TimeSpan duration))
            {
                _cache.Write(cacheKey, result, now + duration);
            }

            return result;
        }

        return new SecretValidationResult(SecretValidationState.Skipped, "no live validator supports the finding");
    }

    /// <summary>
    /// Releases provider validators owned by this verifier.
    /// </summary>
    public void Dispose()
    {
        for (int i = 0; i < _validators.Length; i++)
        {
            if (_validators[i] is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
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
