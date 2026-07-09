using Picket.Sources;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Google Cloud Storage source enumeration.
/// </summary>
[TestClass]
public sealed class GcsSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that GCS JSON metadata stops before reading responses that declare a size beyond the metadata cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsRejectsMetadataResponseExceedingCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ =>
        {
            HttpResponseMessage response = JsonResponse("{}");
            response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
            return response;
        }));
        var client = new GcsSourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("exceeding the 10000000 byte metadata cap", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that GCS JSON metadata is capped while streaming when no content length is available.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsRejectsStreamingMetadataResponseExceedingCap()
    {
        const string Token = "gcs-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => OversizedStreamingJsonMetadataResponse()));
        var client = new GcsSourceClient(httpClient);
        var options = CreateOptions(warnings.Add, Token);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("GCS source metadata", warnings[0]);
        Assert.Contains("remote metadata response exceeded the 10000000 byte metadata cap", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that GCS metadata listing retries one bounded rate-limit response.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsRetriesRateLimitedListRequests()
    {
        var warnings = new List<string>();
        int listAttempts = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            listAttempts++;
            return listAttempts == 1
                ? RetryAfterResponse()
                : JsonResponse("{}");
        });
        using var httpClient = new HttpClient(handler);
        var client = new GcsSourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.IsEmpty(warnings);
        Assert.AreEqual(2, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that GCS object downloads stop when the body exceeds the byte cap even if the declared length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsAppliesByteLimitToUnderstatedContentLength()
    {
        const string Token = "gcs-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/storage/v1/b/secrets/o?", StringComparison.Ordinal)
                && !url.Contains("alt=media", StringComparison.Ordinal))
            {
                return JsonResponse("""{"items":[{"name":"prod/secret.txt","size":"4"}]}""");
            }

            HttpResponseMessage response = BytesResponse("0123456789");
            response.Content.Headers.ContentLength = 1;
            return response;
        }));
        var client = new GcsSourceClient(httpClient);
        var options = CreateOptions(warnings.Add, Token, maxFileBytes: 4);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("GCS object byte limit skipped gcs/secrets/prod/secret.txt", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    private static GcsSourceOptions CreateOptions(
        Action<string> warningSink,
        string credential = "gcs-test-token",
        long? maxFileBytes = null)
    {
        return new GcsSourceOptions(
            GcsSourceOptions.CreateDefaultEndpoint(),
            "secrets",
            credential,
            maxFileBytes: maxFileBytes,
            warningSink: warningSink);
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage OversizedStreamingJsonMetadataResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatingReadStream(RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1, (byte)' ')),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return response;
    }

    private static HttpResponseMessage BytesResponse(string text)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(text)),
        };
    }

    private static HttpResponseMessage RetryAfterResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
        return response;
    }
}
