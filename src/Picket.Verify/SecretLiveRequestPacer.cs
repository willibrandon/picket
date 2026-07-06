namespace Picket.Verify;

internal sealed class SecretLiveRequestPacer(TimeSpan minimumInterval, TimeProvider timeProvider) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TimeSpan _minimumInterval = minimumInterval;
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private DateTimeOffset _nextRequestTime;

    internal async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        if (_minimumInterval == TimeSpan.Zero)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            if (_nextRequestTime > now)
            {
                await Task.Delay(_nextRequestTime - now, _timeProvider, cancellationToken).ConfigureAwait(false);
                now = _timeProvider.GetUtcNow();
            }

            _nextRequestTime = now + _minimumInterval;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        _gate.Dispose();
    }
}
