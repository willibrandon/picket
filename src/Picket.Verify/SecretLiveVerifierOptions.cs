using Picket.Security;

namespace Picket.Verify;

/// <summary>
/// Configures live verification orchestration.
/// </summary>
public sealed class SecretLiveVerifierOptions
{
    internal const int DefaultMaxConcurrentProviderRequests = 4;
    internal const int DefaultMaxConcurrentRequestsPerProvider = 1;

    private EndpointGuardOptions _endpointGuardOptions = EndpointGuardOptions.CreateDefault();
    private TimeSpan _activeResultCacheDuration = TimeSpan.FromMinutes(15);
    private TimeSpan _inactiveResultCacheDuration = TimeSpan.FromHours(1);
    private TimeSpan _skippedResultCacheDuration = TimeSpan.FromMinutes(30);
    private TimeSpan _errorResultCacheDuration = TimeSpan.FromMinutes(5);
    private TimeSpan _minimumRequestInterval = TimeSpan.Zero;
    private TimeSpan _minimumRequestIntervalPerProvider = TimeSpan.FromSeconds(1);
    private int _maxConcurrentProviderRequests = DefaultMaxConcurrentProviderRequests;
    private int _maxConcurrentRequestsPerProvider = DefaultMaxConcurrentRequestsPerProvider;
    private TimeProvider _timeProvider = TimeProvider.System;
    private Action<string>? _warningSink;

    /// <summary>
    /// Creates default live verifier options.
    /// </summary>
    /// <returns>Default live verifier options.</returns>
    public static SecretLiveVerifierOptions CreateDefault()
    {
        return new SecretLiveVerifierOptions();
    }

    /// <summary>
    /// Gets or sets the endpoint guard options applied before a provider validator can run.
    /// </summary>
    /// <remarks>
    /// This preflight guard complements provider-specific connect-time guards such as
    /// <see cref="GitHubSecretLiveValidatorOptions.EndpointGuardOptions" />. When constructing
    /// validators manually, configure both surfaces with equivalent policy.
    /// </remarks>
    public EndpointGuardOptions EndpointGuardOptions
    {
        get => _endpointGuardOptions;
        set => _endpointGuardOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the cache duration for active credential results.
    /// </summary>
    public TimeSpan ActiveResultCacheDuration
    {
        get => _activeResultCacheDuration;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _activeResultCacheDuration = value;
        }
    }

    /// <summary>
    /// Gets or sets the cache duration for inactive credential results.
    /// </summary>
    public TimeSpan InactiveResultCacheDuration
    {
        get => _inactiveResultCacheDuration;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _inactiveResultCacheDuration = value;
        }
    }

    /// <summary>
    /// Gets or sets the cache duration for skipped live verification results.
    /// </summary>
    public TimeSpan SkippedResultCacheDuration
    {
        get => _skippedResultCacheDuration;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _skippedResultCacheDuration = value;
        }
    }

    /// <summary>
    /// Gets or sets the cache duration for provider, network, policy, and rate-limit errors.
    /// </summary>
    public TimeSpan ErrorResultCacheDuration
    {
        get => _errorResultCacheDuration;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _errorResultCacheDuration = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of provider requests that can run at once across all providers.
    /// </summary>
    public int MaxConcurrentProviderRequests
    {
        get => _maxConcurrentProviderRequests;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxConcurrentProviderRequests = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of provider requests that can run at once for one provider.
    /// </summary>
    public int MaxConcurrentRequestsPerProvider
    {
        get => _maxConcurrentRequestsPerProvider;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxConcurrentRequestsPerProvider = value;
        }
    }

    /// <summary>
    /// Gets or sets the minimum interval between provider requests across all providers.
    /// </summary>
    public TimeSpan MinimumRequestInterval
    {
        get => _minimumRequestInterval;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _minimumRequestInterval = value;
        }
    }

    /// <summary>
    /// Gets or sets the minimum interval between provider requests for the same provider.
    /// </summary>
    public TimeSpan MinimumRequestIntervalPerProvider
    {
        get => _minimumRequestIntervalPerProvider;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _minimumRequestIntervalPerProvider = value;
        }
    }

    /// <summary>
    /// Gets or sets the clock used for request-rate pacing.
    /// </summary>
    public TimeProvider TimeProvider
    {
        get => _timeProvider;
        set => _timeProvider = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the callback that receives non-fatal verification warnings.
    /// </summary>
    public Action<string>? WarningSink
    {
        get => _warningSink;
        set => _warningSink = value;
    }

    internal bool TryGetCacheDuration(SecretValidationState state, out TimeSpan duration)
    {
        duration = state switch
        {
            SecretValidationState.Active => ActiveResultCacheDuration,
            SecretValidationState.Inactive => InactiveResultCacheDuration,
            SecretValidationState.Skipped => SkippedResultCacheDuration,
            SecretValidationState.Error => ErrorResultCacheDuration,
            _ => TimeSpan.Zero,
        };

        return duration > TimeSpan.Zero;
    }
}
