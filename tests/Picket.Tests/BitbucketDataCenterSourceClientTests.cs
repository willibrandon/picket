using Picket.Sources;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Bitbucket Data Center source enumeration.
/// </summary>
[TestClass]
public sealed class BitbucketDataCenterSourceClientTests
{
    private const string CommitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string CommitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Data Center credentials require HTTPS by default.
    /// </summary>
    [TestMethod]
    public void OptionsRejectInsecureCredentialTransportByDefault()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new BitbucketDataCenterSourceOptions(
            new Uri("http://bitbucket.example/rest/api/1.0/"),
            "CORE",
            "test-token"));

        Assert.Contains("require HTTPS", ex.Message);
    }

    /// <summary>
    /// Verifies that Data Center Basic authentication requires a username.
    /// </summary>
    [TestMethod]
    public void OptionsRequireUsernameForBasicAuthentication()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            repositorySlug: "picket",
            credentialKind: BitbucketDataCenterCredentialKind.Basic));

        Assert.AreEqual("username", ex.ParamName);
    }

    /// <summary>
    /// Verifies that repository enumeration resolves the default branch to an immutable commit before reading files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesResolvesDefaultBranchCommit()
    {
        const string Token = "data-center-test-token";
        var requests = new List<string>();
        var authorizations = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            authorizations.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            if (url.EndsWith("/projects/CORE/repos/picket/default-branch", StringComparison.Ordinal))
            {
                return JsonResponse($$"""{"id":"refs/heads/main","latestCommit":"{{CommitA}}"}""");
            }

            if (url.Contains($"/projects/CORE/repos/picket/files?at={CommitA}", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":true,"values":["src/appsettings.json"]}""");
            }

            if (url.Contains($"/projects/CORE/repos/picket/raw/src/appsettings.json?at={CommitA}", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(CreateEndpoint(), "CORE", Token, "picket");

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("bitbucket-data-center/CORE/picket/src/appsettings.json", files[0].DisplayPath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("Bearer data-center-test-token", authorizations);
        Assert.Contains($"/files?at={CommitA}&limit=100&start=0", string.Join('\n', requests));
        Assert.DoesNotContain(Token, string.Join('\n', requests));
    }

    /// <summary>
    /// Verifies that named refs are resolved through the commit listing before file enumeration.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesResolvesNamedRefToCommit()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            if (url.Contains("/commits?limit=1&until=feature%2Fwork", StringComparison.Ordinal))
            {
                return JsonResponse($$"""{"isLastPage":true,"values":[{"id":"{{CommitB}}"}]}""");
            }

            if (url.Contains($"/files?at={CommitB}", StringComparison.Ordinal))
            {
                return EmptyPageResponse();
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: "feature/work");

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        string requestText = string.Join('\n', requests);
        Assert.Contains("/commits?limit=1&until=feature%2Fwork", requestText);
        Assert.Contains($"/files?at={CommitB}&limit=100&start=0", requestText);
    }

    /// <summary>
    /// Verifies that project repository enumeration follows the server-provided next-page cursor.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesFollowsProjectPaginationCursor()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            if (url.EndsWith("/projects/CORE/repos?limit=100&start=0", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":false,"nextPageStart":17,"values":[{"slug":"one"}]}""");
            }

            if (url.EndsWith("/projects/CORE/repos?limit=100&start=17", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":true,"values":[{"slug":"two"}]}""");
            }

            if (url.Contains("/default-branch", StringComparison.Ordinal))
            {
                return JsonResponse($$"""{"latestCommit":"{{CommitA}}"}""");
            }

            if (url.Contains("/files?", StringComparison.Ordinal))
            {
                return EmptyPageResponse();
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(CreateEndpoint(), "CORE", "test-token");

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        string requestText = string.Join('\n', requests);
        Assert.Contains("/projects/CORE/repos?limit=100&start=17", requestText);
        Assert.Contains("/projects/CORE/repos/one/files", requestText);
        Assert.Contains("/projects/CORE/repos/two/files", requestText);
    }

    /// <summary>
    /// Verifies that pull request enumeration scans the immutable source commit and source repository, including forks.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesReadsPullRequestSourceRepository()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            if (url.EndsWith("/projects/CORE/repos/picket/pull-requests/7", StringComparison.Ordinal))
            {
                return JsonResponse(
                    $$"""
                    {
                      "fromRef": {
                        "latestCommit": "{{CommitB}}",
                        "repository": {
                          "slug": "picket-fork",
                          "project": { "key": "FORK" }
                        }
                      }
                    }
                    """);
            }

            if (url.Contains($"/projects/FORK/repos/picket-fork/files?at={CommitB}", StringComparison.Ordinal))
            {
                return EmptyPageResponse();
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            pullRequestId: 7);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        string requestText = string.Join('\n', requests);
        Assert.Contains("/projects/CORE/repos/picket/pull-requests/7", requestText);
        Assert.Contains($"/projects/FORK/repos/picket-fork/files?at={CommitB}", requestText);
    }

    /// <summary>
    /// Verifies that Basic authentication uses the configured username and credential.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesUsesBasicAuthentication()
    {
        string authorization = string.Empty;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            authorization = request.Headers.Authorization?.ToString() ?? string.Empty;
            return EmptyPageResponse();
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "password",
            "picket",
            "brandon",
            BitbucketDataCenterCredentialKind.Basic,
            CommitA);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual("Basic YnJhbmRvbjpwYXNzd29yZA==", authorization);
    }

    /// <summary>
    /// Verifies that file paths returned by the provider cannot inject traversal segments into request or display paths.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesNormalizesUnsafeProviderPaths()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            requests.Add(url);
            if (url.Contains("/files?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":true,"values":["safe/../secret.txt"]}""");
            }

            if (url.Contains("/raw/safe/_/secret.txt", StringComparison.Ordinal))
            {
                return BytesResponse("secret");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(CreateEndpoint(), "CORE", "test-token", "picket", gitRef: CommitA);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("bitbucket-data-center/CORE/picket/safe/_/secret.txt", files[0].DisplayPath);
        Assert.Contains("/raw/safe/_/secret.txt", string.Join('\n', requests));
        Assert.DoesNotContain("/../", string.Join('\n', requests));
    }

    /// <summary>
    /// Verifies that metadata responses declaring a size beyond the fixed cap are rejected before parsing.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesRejectsOversizedMetadata()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => OversizedMetadataResponse()));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: "main",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Bitbucket Data Center source metadata", warnings[0]);
    }

    /// <summary>
    /// Verifies that declared file sizes above the configured cap are skipped without reading the body.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesRejectsDeclaredOversizedContent()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/files", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":true,"values":["large.bin"]}""");
            }

            HttpResponseMessage response = BytesResponse("too-large");
            response.Content.Headers.ContentLength = 9;
            return response;
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: CommitA,
            maxFileBytes: 8,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("file byte limit skipped", warnings[0]);
    }

    /// <summary>
    /// Verifies that streamed file bodies remain bounded when the server omits Content-Length.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesRejectsStreamedOversizedContent()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("/files", StringComparison.Ordinal))
            {
                return JsonResponse("""{"isLastPage":true,"values":["large.bin"]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes("too-large"), writable: false)),
            };
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: CommitA,
            maxFileBytes: 8,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("file byte limit skipped", warnings[0]);
    }

    /// <summary>
    /// Verifies that a non-advancing provider cursor stops pagination without repeating requests.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesStopsAtNonAdvancingPaginationCursor()
    {
        var warnings = new List<string>();
        int requests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ =>
        {
            requests++;
            return JsonResponse("""{"isLastPage":false,"nextPageStart":0,"values":[]}""");
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1, requests);
        Assert.HasCount(1, warnings);
        Assert.Contains("invalid pagination cursor", warnings[0]);
    }

    /// <summary>
    /// Verifies that cancellation requested before enumeration prevents outbound requests.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesStopsBeforeRequestWhenCancelled()
    {
        int requests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ =>
        {
            requests++;
            return EmptyPageResponse();
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            isCancellationRequested: static () => true);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(0, requests);
    }

    /// <summary>
    /// Verifies that global path filtering runs before raw file content is requested.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesSkipsFilteredPathBeforeDownload()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = request.RequestUri!.AbsolutePath;
            requests.Add(path);
            return path.Contains("/files", StringComparison.Ordinal)
                ? JsonResponse("""{"isLastPage":true,"values":["ignored/secret.txt"]}""")
                : BytesResponse("secret");
        }));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: CommitA,
            isPathAllowed: static path => path.EndsWith("secret.txt", StringComparison.Ordinal));

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, requests);
        Assert.Contains("/files", requests[0]);
    }

    /// <summary>
    /// Verifies that retryable responses are retried once with the same bounded request contract.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesRetriesOneRateLimitedRequest()
    {
        int attempts = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ => ++attempts == 1
            ? RetryAfterResponse()
            : EmptyPageResponse()));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(CreateEndpoint(), "CORE", "test-token", "picket", gitRef: CommitA);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, attempts);
    }

    /// <summary>
    /// Verifies that responses already redirected by an injected handler are rejected before parsing.
    /// </summary>
    [TestMethod]
    public async Task EnumerateFilesBlocksAutoFollowedRedirects()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => AutoRedirectedResponse()));
        var client = new BitbucketDataCenterSourceClient(httpClient);
        var options = new BitbucketDataCenterSourceOptions(
            CreateEndpoint(),
            "CORE",
            "test-token",
            "picket",
            gitRef: CommitA,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("HTTP 421", warnings[0]);
    }

    private static Uri CreateEndpoint()
    {
        return new Uri("https://bitbucket.example/rest/api/1.0/", UriKind.Absolute);
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage EmptyPageResponse()
    {
        return JsonResponse("""{"isLastPage":true,"values":[]}""");
    }

    private static HttpResponseMessage BytesResponse(string value)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(value)),
        };
    }

    private static HttpResponseMessage OversizedMetadataResponse()
    {
        HttpResponseMessage response = JsonResponse("{}");
        response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
        return response;
    }

    private static HttpResponseMessage RetryAfterResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
        return response;
    }

    private static HttpResponseMessage AutoRedirectedResponse()
    {
        HttpResponseMessage response = EmptyPageResponse();
        response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://attacker.example/redirected");
        return response;
    }
}
