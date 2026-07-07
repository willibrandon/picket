using System.Net;

namespace Picket.Sources;

internal static class RemoteSourceHttpRetry
{
    private const int MaxRetryAttempts = 1;
    private static readonly TimeSpan s_defaultRetryDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan s_maxRetryDelay = TimeSpan.FromSeconds(5);

    internal static async Task<HttpResponseMessage> SendAsync(
        HttpClient httpClient,
        Func<HttpRequestMessage> requestFactory,
        Func<HttpResponseMessage, bool> isRetryableResponse,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            HttpRequestMessage request = requestFactory();
            Uri? requestUri = request.RequestUri;
            HttpResponseMessage response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (requestUri is not null && WasAutoRedirected(response, request, requestUri))
            {
                response.Dispose();
                return CreateAutoRedirectBlockedResponse(request);
            }

            if (attempt >= MaxRetryAttempts || !isRetryableResponse(response))
            {
                return response;
            }

            TimeSpan retryDelay = GetRetryDelay(response);
            response.Dispose();
            if (retryDelay > TimeSpan.Zero)
            {
                await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static bool WasAutoRedirected(
        HttpResponseMessage response,
        HttpRequestMessage request,
        Uri requestUri)
    {
        HttpRequestMessage? responseRequest = response.RequestMessage;
        if (responseRequest is null
            || ReferenceEquals(responseRequest, request)
            || responseRequest.RequestUri is null)
        {
            return false;
        }

        return !responseRequest.RequestUri.AbsoluteUri.Equals(requestUri.AbsoluteUri, StringComparison.Ordinal);
    }

    private static HttpResponseMessage CreateAutoRedirectBlockedResponse(HttpRequestMessage request)
    {
        return new HttpResponseMessage((HttpStatusCode)421)
        {
            ReasonPhrase = "Automatic redirect blocked",
            RequestMessage = request,
        };
    }

    internal static bool IsGenericRetryableResponse(HttpResponseMessage response)
    {
        return response.StatusCode is HttpStatusCode.TooManyRequests
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout
            || response.Headers.RetryAfter is not null;
    }

    private static TimeSpan GetRetryDelay(HttpResponseMessage response)
    {
        TimeSpan retryDelay = response.Headers.RetryAfter?.Delta
            ?? GetDateRetryDelay(response)
            ?? s_defaultRetryDelay;
        if (retryDelay < TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        return retryDelay > s_maxRetryDelay ? s_maxRetryDelay : retryDelay;
    }

    private static TimeSpan? GetDateRetryDelay(HttpResponseMessage response)
    {
        DateTimeOffset? date = response.Headers.RetryAfter?.Date;
        return date.HasValue ? date.Value - DateTimeOffset.UtcNow : null;
    }
}
