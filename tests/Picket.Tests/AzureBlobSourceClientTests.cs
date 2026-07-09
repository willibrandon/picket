using Picket.Sources;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Azure Blob Storage source enumeration.
/// </summary>
[TestClass]
public sealed class AzureBlobSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Azure Blob XML metadata rejects DTDs.
    /// </summary>
    [TestMethod]
    public async Task EnumerateBlobsRejectsDtdMetadata()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => XmlResponse(
            """
            <!DOCTYPE EnumerationResults [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <EnumerationResults><Blobs><Blob><Name>&xxe;</Name><Properties><Content-Length>1</Content-Length></Properties></Blob></Blobs></EnumerationResults>
            """)));
        var client = new AzureBlobSourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateBlobsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("XML parsing failed", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that Azure Blob XML metadata stops before reading responses that declare a size beyond the metadata cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateBlobsRejectsMetadataResponseExceedingCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ =>
        {
            HttpResponseMessage response = XmlResponse("<EnumerationResults />");
            response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
            return response;
        }));
        var client = new AzureBlobSourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateBlobsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("exceeding the 10000000 byte metadata cap", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that Azure Blob warnings do not echo SAS query credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumerateBlobsWarningsNeverContainSasToken()
    {
        var requests = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            if (url.Contains("comp=list", StringComparison.Ordinal))
            {
                return XmlResponse(
                    """
                    <EnumerationResults>
                      <Blobs>
                        <Blob><Name>secret.txt</Name><Properties><Content-Length>1</Content-Length></Properties></Blob>
                      </Blobs>
                    </EnumerationResults>
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.Forbidden);
        }));
        var client = new AzureBlobSourceClient(httpClient);
        var options = CreateOptions(warnings.Add);

        List<SourceFile> files = await client.EnumerateBlobsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string warningText = string.Join('\n', warnings);
        Assert.IsEmpty(files);
        Assert.Contains("sig=secret-signature", string.Join('\n', requests));
        Assert.Contains("skipping Azure Blob azure-blob/picket.blob.core.windows.net/logs/secret.txt", warningText);
        Assert.DoesNotContain("secret-signature", warningText);
        Assert.DoesNotContain("sig=", warningText);
    }

    /// <summary>
    /// Verifies that Azure Blob downloads stop when the body exceeds the byte cap even if the declared length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateBlobsAppliesByteLimitToUnderstatedContentLength()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("comp=list", StringComparison.Ordinal))
            {
                return XmlResponse(
                    """
                    <EnumerationResults>
                      <Blobs>
                        <Blob><Name>prod/secret.txt</Name><Properties><Content-Length>4</Content-Length></Properties></Blob>
                      </Blobs>
                    </EnumerationResults>
                    """);
            }

            HttpResponseMessage response = BytesResponse("0123456789");
            response.Content.Headers.ContentLength = 1;
            return response;
        }));
        var client = new AzureBlobSourceClient(httpClient);
        var options = CreateOptions(warnings.Add, maxFileBytes: 4);

        List<SourceFile> files = await client.EnumerateBlobsAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure Blob byte limit skipped azure-blob/picket.blob.core.windows.net/logs/prod/secret.txt", warnings[0]);
        Assert.DoesNotContain("secret-signature", warnings[0]);
    }

    private static AzureBlobSourceOptions CreateOptions(Action<string> warningSink, long? maxFileBytes = null)
    {
        return new AzureBlobSourceOptions(
            new Uri("https://picket.blob.core.windows.net/"),
            "logs",
            "sv=2026-04-06&sig=secret-signature",
            AzureBlobCredentialKind.SharedAccessSignature,
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
