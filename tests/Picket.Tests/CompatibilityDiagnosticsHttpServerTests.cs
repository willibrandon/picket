using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="CompatibilityDiagnosticsHttpServer" />.
/// </summary>
[TestClass]
public sealed class CompatibilityDiagnosticsHttpServerTests
{
    /// <summary>
    /// Gets or sets the test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the diagnostics server binds loopback and serves authorized GET requests.
    /// </summary>
    [TestMethod]
    public async Task StartBindsLoopbackAndReturnsAuthorizedGet()
    {
        int calls = 0;
        string observedPath = string.Empty;
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(path =>
        {
            calls++;
            observedPath = path;
            return new CompatibilityDiagnosticsHttpResponse("application/json; charset=utf-8", "{\"ok\":true}");
        });

        var uri = new Uri(server.DiagnosticsUri);
        using var client = new HttpClient();
        using HttpResponseMessage response = await client.GetAsync(uri, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("127.0.0.1", uri.Host);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("{\"ok\":true}", body);
        Assert.AreEqual("/debug/pprof/", observedPath);
        Assert.AreEqual(1, calls);
    }

    /// <summary>
    /// Verifies requests without the capability token are rejected before the response factory runs.
    /// </summary>
    [TestMethod]
    public async Task RequestWithoutTokenReturnsUnauthorized()
    {
        int calls = 0;
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(_ =>
        {
            calls++;
            return new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "ok\n");
        });

        using var client = new HttpClient();
        using HttpResponseMessage response = await client.GetAsync(CreateUriWithoutQuery(server), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.AreEqual("unauthorized\n", body);
        Assert.AreEqual(0, calls);
    }

    /// <summary>
    /// Verifies authorized HEAD requests are allowed and do not include a response body.
    /// </summary>
    [TestMethod]
    public async Task AuthorizedHeadReturnsNoBody()
    {
        int calls = 0;
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(_ =>
        {
            calls++;
            return new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "body\n");
        });

        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Head, server.DiagnosticsUri);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsEmpty(body);
        Assert.AreEqual(0, response.Content.Headers.ContentLength);
        Assert.AreEqual(1, calls);
    }

    /// <summary>
    /// Verifies authorized methods outside GET and HEAD are rejected before the response factory runs.
    /// </summary>
    [TestMethod]
    public async Task AuthorizedPostReturnsMethodNotAllowed()
    {
        int calls = 0;
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(_ =>
        {
            calls++;
            return new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "ok\n");
        });

        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, server.DiagnosticsUri);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.AreEqual("method not allowed\n", body);
        Assert.AreEqual(0, calls);
    }

    /// <summary>
    /// Verifies malformed request lines are rejected.
    /// </summary>
    [TestMethod]
    public async Task MalformedRequestReturnsBadRequest()
    {
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(_ =>
            new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "ok\n"));

        string response = await SendRawRequestAsync(new Uri(server.DiagnosticsUri), "not-http\r\n\r\n", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains("HTTP/1.1 400 Bad Request", response);
        Assert.Contains("bad request\n", response);
    }

    /// <summary>
    /// Verifies oversized headers are capped and cannot make an authorized request hang.
    /// </summary>
    [TestMethod]
    public async Task OversizedHeaderDoesNotBlockAuthorizedRequest()
    {
        using CompatibilityDiagnosticsHttpServer server = CompatibilityDiagnosticsHttpServer.Start(_ =>
            new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "ok\n"));

        var uri = new Uri(server.DiagnosticsUri);
        string request = string.Concat(
            "GET ",
            uri.PathAndQuery,
            " HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fill: ",
            new string('x', 9000));

        string response = await SendRawRequestAsync(uri, request, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains("HTTP/1.1 200 OK", response);
        Assert.Contains("Content-Length: 3", response);
    }

    private static Uri CreateUriWithoutQuery(CompatibilityDiagnosticsHttpServer server)
    {
        var builder = new UriBuilder(server.DiagnosticsUri)
        {
            Query = string.Empty
        };

        return builder.Uri;
    }

    private static async Task<string> SendRawRequestAsync(Uri uri, string request, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(uri.Host, uri.Port, cancellationToken).ConfigureAwait(false);
        using NetworkStream stream = client.GetStream();
        byte[] requestBytes = Encoding.ASCII.GetBytes(request);
        await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] buffer = new byte[4096];
        using var response = new MemoryStream();
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
            {
                response.Write(buffer.AsSpan(0, read));
            }
        }
        catch (IOException) when (response.Length > 0)
        {
        }

        return Encoding.UTF8.GetString(response.ToArray());
    }
}
