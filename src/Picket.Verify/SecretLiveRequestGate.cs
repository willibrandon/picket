namespace Picket.Verify;

/// <summary>
/// Applies verifier-wide policy to requests from one validation operation.
/// </summary>
internal sealed class SecretLiveRequestGate(
    SecretLiveVerifier verifier,
    string provider) : ISecretLiveRequestGate
{
    private int _requestCount;

    /// <inheritdoc />
    public int RequestCount => Volatile.Read(ref _requestCount);

    /// <inheritdoc />
    public ValueTask<T> ExecuteAsync<T>(
        Func<CancellationToken, ValueTask<T>> request,
        CancellationToken cancellationToken)
    {
        return verifier.ExecuteProviderRequestAsync(
            provider,
            request,
            RecordRequestStarted,
            cancellationToken);
    }

    private void RecordRequestStarted()
    {
        Interlocked.Increment(ref _requestCount);
    }
}
