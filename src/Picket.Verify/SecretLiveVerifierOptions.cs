using Picket.Security;

namespace Picket.Verify;

/// <summary>
/// Configures live verification orchestration.
/// </summary>
public sealed class SecretLiveVerifierOptions
{
    private EndpointGuardOptions _endpointGuardOptions = EndpointGuardOptions.CreateDefault();
    private TimeSpan _activeResultCacheDuration = TimeSpan.FromMinutes(15);
    private TimeSpan _inactiveResultCacheDuration = TimeSpan.FromHours(1);
    private TimeSpan _skippedResultCacheDuration = TimeSpan.FromMinutes(30);
    private TimeSpan _errorResultCacheDuration = TimeSpan.FromMinutes(5);

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
