namespace Picket.Tests;

/// <summary>
/// Provides an HTTP handler that waits until the request is cancelled.
/// </summary>
internal sealed class CancellableHttpMessageHandler : HttpMessageHandler
{
    internal int RequestCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount++;
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException("Cancellation did not stop the request.");
    }
}
