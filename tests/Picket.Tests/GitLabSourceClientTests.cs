using Picket.Sources;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests GitLab source enumeration.
/// </summary>
[TestClass]
public sealed class GitLabSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that GitLab source options default to bounded remote downloads.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsDefaultsToBoundedRemoteDownloads()
    {
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token");

        Assert.AreEqual(100_000_000, options.MaxFileBytes);
    }

    /// <summary>
    /// Verifies that GitLab source options reject unbounded remote downloads.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsZeroForUnboundedRemoteDownloads()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            maxFileBytes: 0));
    }

    /// <summary>
    /// Verifies that GitLab project URLs normalize to project paths.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsNormalizesProjectUrls()
    {
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "https://gitlab.com/willibrandon/picket.git",
            "gitlab-test-token");

        Assert.AreEqual("willibrandon/picket", options.Project);
    }

    /// <summary>
    /// Verifies that repository enumeration reads the project tree and downloads raw blob content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsTreeAndRawContent()
    {
        const string Token = "gitlab-test-token";
        var urls = new List<string>();
        var privateTokens = new List<string>();
        var authorizationHeaders = new List<string>();
        var acceptHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            CaptureRequest(request, urls, privateTokens, authorizationHeaders, acceptHeaders);
            string url = request.RequestUri!.ToString();
            if (url.Contains("/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
            {
                var response = JsonResponse(
                    """
                    [
                      { "path": "src/appsettings.txt", "type": "blob", "size": 11 },
                      { "path": "src", "type": "tree" }
                    ]
                    """);
                return response;
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(GitLabSourceOptions.CreateDefaultEndpoint(), "willibrandon/picket", Token);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab/willibrandon/picket/src/appsettings.txt", files[0].DisplayPath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("recursive=true", string.Join('\n', urls));
        Assert.Contains("ref=main", string.Join('\n', urls));
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", acceptHeaders);
    }

    /// <summary>
    /// Verifies that repository enumeration skips files that exceed the configured byte cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsOversizedTreeEntries()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "path": "huge.bin", "type": "blob", "size": 12 }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            maxFileBytes: 4,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("GitLab file byte limit skipped gitlab/willibrandon/picket/huge.bin", string.Join('\n', warnings));
    }

    private static void CaptureRequest(
        HttpRequestMessage request,
        List<string> urls,
        List<string> privateTokens,
        List<string> authorizationHeaders,
        List<string> acceptHeaders)
    {
        urls.Add(request.RequestUri!.ToString());
        privateTokens.Add(request.Headers.TryGetValues("PRIVATE-TOKEN", out IEnumerable<string>? privateTokenValues)
            ? string.Concat("PRIVATE-TOKEN ", string.Join(" ", privateTokenValues))
            : string.Empty);
        authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
        acceptHeaders.Add(string.Join('\n', request.Headers.Accept.Select(static value => value.MediaType ?? string.Empty)));
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage BytesResponse(string text)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(text)),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return response;
    }
}
