using Picket.Sources;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Amazon S3 source enumeration.
/// </summary>
[TestClass]
public sealed class S3SourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that S3 XML metadata rejects DTDs.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsRejectsDtdMetadata()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => XmlResponse(
            """
            <!DOCTYPE ListBucketResult [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <ListBucketResult><Contents><Key>&xxe;</Key><Size>1</Size></Contents></ListBucketResult>
            """)));
        var client = new S3SourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("XML parsing failed", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that S3 XML metadata stops before reading responses that declare a size beyond the metadata cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsRejectsMetadataResponseExceedingCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ =>
        {
            HttpResponseMessage response = XmlResponse("<ListBucketResult />");
            response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
            return response;
        }));
        var client = new S3SourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("exceeding the 10000000 byte metadata cap", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that S3 object downloads stop when the body exceeds the byte cap even if the declared length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateObjectsAppliesByteLimitToUnderstatedContentLength()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("list-type=2", StringComparison.Ordinal))
            {
                return XmlResponse(
                    """
                    <ListBucketResult>
                      <Contents><Key>logs/secret.txt</Key><Size>4</Size></Contents>
                    </ListBucketResult>
                    """);
            }

            HttpResponseMessage response = BytesResponse("0123456789");
            response.Content.Headers.ContentLength = 1;
            return response;
        }));
        var client = new S3SourceClient(httpClient);
        var options = CreateOptions(warnings.Add, maxFileBytes: 4);

        List<SourceFile> files = await client.EnumerateObjectsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("S3 object byte limit skipped s3/examplebucket/logs/secret.txt", warnings[0]);
        Assert.DoesNotContain("wJalrXUtnFEMI", warnings[0]);
    }

    private static S3SourceOptions CreateOptions(Action<string> warningSink, long? maxFileBytes = null)
    {
        return new S3SourceOptions(
            new Uri("https://s3.us-east-1.amazonaws.com/"),
            "examplebucket",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            maxFileBytes: maxFileBytes,
            warningSink: warningSink);
    }

    private static HttpResponseMessage XmlResponse(string xml)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(xml, Encoding.UTF8, "application/xml"),
        };
    }

    private static HttpResponseMessage BytesResponse(string text)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(text)),
        };
    }
}
