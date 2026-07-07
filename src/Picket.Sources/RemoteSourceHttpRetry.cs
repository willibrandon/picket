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
            HttpResponseMessage response = await httpClient.SendAsync(
                requestFactory(),
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
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
