namespace Picket.Tests;

internal sealed class FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder = responder;

    internal HttpRequestMessage? LastRequest { get; private set; }

    internal int RequestCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LastRequest = request;
        RequestCount++;
        return Task.FromResult(_responder(request));
    }
}
