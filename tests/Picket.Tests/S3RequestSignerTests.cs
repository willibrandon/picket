using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests Amazon S3 SigV4 request signing.
/// </summary>
[TestClass]
public sealed class S3RequestSignerTests
{
    /// <summary>
    /// Verifies that S3 signing matches an independently checked AWS SigV4 known-answer request.
    /// </summary>
    [TestMethod]
    public void SignMatchesAwsSigV4KnownAnswer()
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            "https://examplebucket.s3.amazonaws.com/test.txt?partNumber=1&x-id=GetObject");
        var options = new S3SourceOptions(
            new Uri("https://examplebucket.s3.amazonaws.com/"),
            "examplebucket",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        S3RequestSigner.Sign(request, options, new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero));

        Assert.AreEqual("examplebucket.s3.amazonaws.com", request.Headers.Host);
        Assert.AreEqual("20130524T000000Z", GetHeaderValue(request, "x-amz-date"));
        Assert.AreEqual(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            GetHeaderValue(request, "x-amz-content-sha256"));
        Assert.AreEqual(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=3fc970e6e6bd47e1af189cfa58eea28d40438ab67f3ed6aa85ecf37d8bf546e3",
            GetHeaderValue(request, "Authorization"));
    }

    private static string GetHeaderValue(HttpRequestMessage request, string headerName)
    {
        return request.Headers.TryGetValues(headerName, out IEnumerable<string>? values)
            ? string.Join(',', values)
            : string.Empty;
    }
}
