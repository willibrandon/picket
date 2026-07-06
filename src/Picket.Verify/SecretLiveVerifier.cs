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
                return AddAuditEvidence(
                    new SecretValidationResult(
                        SecretValidationState.Error,
                        string.Concat("endpoint blocked: ", endpointResult.BlockReason.ToString())),
                    validator,
                    endpointResult,
                    providerContacted: false);
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            SecretValidationCacheKey cacheKey = SecretValidationCacheKey.FromFinding(validator.Provider, validator.Version, finding, validator.Endpoint);
            if (_requestCache.TryGetValue(cacheKey.Fingerprint, out SecretValidationResult? requestCachedResult))
            {
                return AddAuditEvidence(
                    requestCachedResult,
                    validator,
                    endpointResult,
                    providerContacted: false,
                    cacheHit: "request");
            }

            if (_cache is not null)
            {
                if (_cache.TryRead(cacheKey, now, out SecretValidationResult? cachedResult))
                {
                    SecretValidationResult auditedCachedResult = AddAuditEvidence(
                        cachedResult,
                        validator,
                        endpointResult,
                        providerContacted: false,
                        cacheHit: "persistent");
                    _requestCache[cacheKey.Fingerprint] = auditedCachedResult;
                    return auditedCachedResult;
                }
            }

            SecretValidationResult result = await validator.VerifyAsync(finding, cancellationToken).ConfigureAwait(false);
            SecretValidationResult auditedResult = AddAuditEvidence(
                result,
                validator,
                endpointResult,
                providerContacted: true);
            _requestCache[cacheKey.Fingerprint] = auditedResult;
            if (_cache is not null && _options.TryGetCacheDuration(auditedResult.State, out TimeSpan duration))
            {
                _cache.Write(cacheKey, auditedResult, now + duration);
            }

            return auditedResult;
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

    private static SecretValidationResult AddAuditEvidence(
        SecretValidationResult result,
        ISecretLiveValidator validator,
        EndpointGuardResult endpointResult,
        bool providerContacted,
        string cacheHit = "")
    {
        var evidence = new List<string>(result.Evidence.Count + 5)
        {
            string.Concat("provider=", validator.Provider),
            string.Concat("endpoint=", NormalizeEndpoint(validator.Endpoint)),
            string.Concat("endpointPolicy=", CreateEndpointPolicy(endpointResult)),
            string.Concat("providerContacted=", providerContacted ? "true" : "false"),
        };

        if (cacheHit.Length != 0)
        {
            evidence.Add(string.Concat("cacheHit=", cacheHit));
        }

        for (int i = 0; i < result.Evidence.Count; i++)
        {
            string value = result.Evidence[i];
            if (!IsVerifierAuditEvidence(value) && !evidence.Contains(value, StringComparer.Ordinal))
            {
                evidence.Add(value);
            }
        }

        return new SecretValidationResult(
            result.State,
            result.Reason,
            result.Identity,
            Copy(result.Scopes),
            Copy(result.ReachableResources),
            [.. evidence]);
    }

    private static string CreateEndpointPolicy(EndpointGuardResult endpointResult)
    {
        return endpointResult.IsAllowed
            ? "allowed"
            : string.Concat("blocked:", endpointResult.BlockReason.ToString());
    }

    private static string NormalizeEndpoint(Uri endpoint)
    {
        return endpoint.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
    }

    private static bool IsVerifierAuditEvidence(string value)
    {
        return value.StartsWith("provider=", StringComparison.Ordinal)
            || value.StartsWith("endpoint=", StringComparison.Ordinal)
            || value.StartsWith("endpointPolicy=", StringComparison.Ordinal)
            || value.StartsWith("providerContacted=", StringComparison.Ordinal)
            || value.StartsWith("cacheHit=", StringComparison.Ordinal);
    }

    private static string[] Copy(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return [];
        }

        var copy = new string[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            copy[i] = values[i];
        }

        return copy;
    }
}
