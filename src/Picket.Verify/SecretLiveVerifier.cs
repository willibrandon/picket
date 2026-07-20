using Picket.Engine;
using Picket.Security;
using System.Diagnostics.CodeAnalysis;

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
    private readonly SemaphoreSlim _globalRequestLimiter = new(options?.MaxConcurrentProviderRequests ?? SecretLiveVerifierOptions.DefaultMaxConcurrentProviderRequests);
    private readonly SecretLiveRequestPacer _globalRequestPacer = CreateRequestPacer(options, perProvider: false);
    private readonly Lock _gate = new();
    private readonly Dictionary<string, SecretLiveRequestPacer> _providerRequestPacers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SemaphoreSlim> _providerRequestLimiters = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (SecretValidationResult Result, DateTimeOffset ExpiresAt)> _requestCache = new(StringComparer.Ordinal);
    private readonly ISecretLiveValidator[] _validators = ValidateValidators(validators);
    private bool _cacheWriteWarningEmitted;

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

            DateTimeOffset now = _options.TimeProvider.GetUtcNow();
            SecretValidationCacheKey cacheKey = SecretValidationCacheKey.FromFinding(validator.Provider, validator.Version, finding, validator.Endpoint);
            if (TryReadRequestCache(cacheKey.Fingerprint, now, out SecretValidationResult? requestCachedResult))
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
                    WriteRequestCacheWhenConfigured(cacheKey.Fingerprint, auditedCachedResult, now);
                    return auditedCachedResult;
                }
            }

            SecretValidationResult result = await VerifyWithRateLimitsAsync(validator, finding, cancellationToken).ConfigureAwait(false);
            SecretValidationResult auditedResult = AddAuditEvidence(
                result,
                validator,
                endpointResult,
                providerContacted: true);
            if (_options.TryGetCacheDuration(auditedResult.State, out TimeSpan duration))
            {
                DateTimeOffset expiresAt = now + duration;
                WriteRequestCache(cacheKey.Fingerprint, auditedResult, expiresAt);
                if (_cache is not null && auditedResult.IsPersistentCacheable)
                {
                    TryWritePersistentCache(cacheKey, auditedResult, expiresAt);
                }
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

        _globalRequestLimiter.Dispose();
        _globalRequestPacer.Dispose();
        lock (_gate)
        {
            foreach (SemaphoreSlim limiter in _providerRequestLimiters.Values)
            {
                limiter.Dispose();
            }

            foreach (SecretLiveRequestPacer pacer in _providerRequestPacers.Values)
            {
                pacer.Dispose();
            }
        }
    }

    private static SecretLiveRequestPacer CreateRequestPacer(SecretLiveVerifierOptions? options, bool perProvider)
    {
        SecretLiveVerifierOptions resolvedOptions = options ?? SecretLiveVerifierOptions.CreateDefault();
        return new SecretLiveRequestPacer(
            perProvider ? resolvedOptions.MinimumRequestIntervalPerProvider : resolvedOptions.MinimumRequestInterval,
            resolvedOptions.TimeProvider);
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

    private async ValueTask<SecretValidationResult> VerifyWithRateLimitsAsync(
        ISecretLiveValidator validator,
        Finding finding,
        CancellationToken cancellationToken)
    {
        SemaphoreSlim providerRequestLimiter = GetProviderRequestLimiter(validator.Provider);
        SecretLiveRequestPacer providerRequestPacer = GetProviderRequestPacer(validator.Provider);
        await providerRequestLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);
        bool globalRequestLimiterAcquired = false;
        try
        {
            await _globalRequestLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);
            globalRequestLimiterAcquired = true;
            await _globalRequestPacer.WaitAsync(cancellationToken).ConfigureAwait(false);
            await providerRequestPacer.WaitAsync(cancellationToken).ConfigureAwait(false);
            return await validator.VerifyAsync(finding, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (globalRequestLimiterAcquired)
            {
                _globalRequestLimiter.Release();
            }

            providerRequestLimiter.Release();
        }
    }

    private SecretLiveRequestPacer GetProviderRequestPacer(string provider)
    {
        lock (_gate)
        {
            if (!_providerRequestPacers.TryGetValue(provider, out SecretLiveRequestPacer? pacer))
            {
                pacer = new SecretLiveRequestPacer(_options.MinimumRequestIntervalPerProvider, _options.TimeProvider);
                _providerRequestPacers.Add(provider, pacer);
            }

            return pacer;
        }
    }

    private SemaphoreSlim GetProviderRequestLimiter(string provider)
    {
        lock (_gate)
        {
            if (!_providerRequestLimiters.TryGetValue(provider, out SemaphoreSlim? limiter))
            {
                limiter = new SemaphoreSlim(_options.MaxConcurrentRequestsPerProvider);
                _providerRequestLimiters.Add(provider, limiter);
            }

            return limiter;
        }
    }

    private bool TryReadRequestCache(
        string fingerprint,
        DateTimeOffset now,
        [NotNullWhen(true)] out SecretValidationResult? result)
    {
        lock (_gate)
        {
            if (_requestCache.TryGetValue(fingerprint, out (SecretValidationResult Result, DateTimeOffset ExpiresAt) entry))
            {
                if (entry.ExpiresAt > now)
                {
                    result = entry.Result;
                    return true;
                }

                _requestCache.Remove(fingerprint);
            }

            result = null;
            return false;
        }
    }

    private void WriteRequestCache(string fingerprint, SecretValidationResult result, DateTimeOffset expiresAt)
    {
        lock (_gate)
        {
            _requestCache[fingerprint] = (result, expiresAt);
        }
    }

    private void WriteRequestCacheWhenConfigured(
        string fingerprint,
        SecretValidationResult result,
        DateTimeOffset now)
    {
        if (_options.TryGetCacheDuration(result.State, out TimeSpan duration))
        {
            WriteRequestCache(fingerprint, result, now + duration);
        }
    }

    private void TryWritePersistentCache(
        SecretValidationCacheKey cacheKey,
        SecretValidationResult result,
        DateTimeOffset expiresAt)
    {
        try
        {
            _cache!.Write(cacheKey, result, expiresAt);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            EmitCacheWriteWarning();
        }
    }

    private void EmitCacheWriteWarning()
    {
        bool emitWarning;
        lock (_gate)
        {
            emitWarning = !_cacheWriteWarningEmitted;
            _cacheWriteWarningEmitted = true;
        }

        if (emitWarning)
        {
            _options.WarningSink?.Invoke("validation cache write failed; continuing without persistent caching");
        }
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
            [.. evidence],
            result.IsPersistentCacheable);
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
