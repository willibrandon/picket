using System.Net;
using System.Text;
using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests GitHub source enumeration.
/// </summary>
[TestClass]
public sealed class GitHubSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that repository enumeration reads the recursive tree and downloads raw blob content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsTreeAndRawContent()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        var acceptHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            CaptureRequest(request, urls, authorizationHeaders, acceptHeaders);
            string url = request.RequestUri!.ToString();
            if (url.Contains("/repos/willibrandon/picket/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "truncated": false,
                      "tree": [
                        { "path": "src/appsettings.txt", "type": "blob", "size": 11 },
                        { "path": "src", "type": "tree" }
                      ]
                    }
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket/contents/src/appsettings.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(GitHubSourceOptions.CreateDefaultEndpoint(), "willibrandon/picket", Token);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("github/willibrandon/picket/src/appsettings.txt", files[0].DisplayPath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("recursive=1", string.Join('\n', urls));
        Assert.Contains("ref=main", string.Join('\n', urls));
        Assert.Contains("Bearer github-test-token", authorizationHeaders);
        Assert.Contains("application/vnd.github.raw", acceptHeaders);
        Assert.Contains("application/vnd.github+json", acceptHeaders);
        Assert.DoesNotContain(Token, string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that an explicit ref skips repository default-branch lookup.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesUsesExplicitRef()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/git/trees/feature%2Fscan?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "https://github.com/willibrandon/picket.git",
            Token,
            "feature/scan");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, urls);
        Assert.DoesNotContain("/repos/willibrandon/picket?", string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that tree file sizes are honored before content is downloaded.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesHonorsTreeFileByteCap()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"large.txt","type":"blob","size":10}]}""");
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            maxFileBytes: 4,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("GitHub file byte limit skipped github/willibrandon/picket/large.txt", warnings[0]);
        Assert.DoesNotContain("/contents/large.txt", string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that per-file download failures are warnings rather than whole-source failures.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsDownloadFailures()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"missing.txt","type":"blob","size":1}]}""");
            }

            if (url.Contains("/contents/missing.txt?", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("skipping GitHub file github/willibrandon/picket/missing.txt", warnings[0]);
        Assert.Contains("404 NotFound", warnings[0]);
    }

    private static void CaptureRequest(
        HttpRequestMessage request,
        List<string> urls,
        List<string> authorizationHeaders,
        List<string> acceptHeaders)
    {
        urls.Add(request.RequestUri!.ToString());
        authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
        acceptHeaders.Add(string.Join(',', request.Headers.Accept.Select(value => value.MediaType)));
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage BytesResponse(string value)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(value)),
        };
    }
}
