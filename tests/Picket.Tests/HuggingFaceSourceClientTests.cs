using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Hugging Face source enumeration.
/// </summary>
[TestClass]
public sealed class HuggingFaceSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that repository resources resolve a revision once and use the immutable commit in paths and downloads.
    /// </summary>
    [TestMethod]
    [DataRow(HuggingFaceResourceKind.Model, "model")]
    [DataRow(HuggingFaceResourceKind.Dataset, "dataset")]
    [DataRow(HuggingFaceResourceKind.Space, "space")]
    public async Task EnumerateRepositoryUsesResolvedCommit(
        HuggingFaceResourceKind resourceKind,
        string resourceName)
    {
        const string Token = "hf-test-token";
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            requests.Add(uri);
            Assert.AreEqual($"Bearer {Token}", request.Headers.Authorization?.ToString());
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"config/secret.txt","size":12}]""");
            }

            if (uri.Contains("/resolve/abc123/", StringComparison.Ordinal))
            {
                return BytesResponse("hf-secret-1");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            resourceKind,
            "owner/project",
            Token);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual(
            $"huggingface/{resourceName}/owner/project/abc123/config/secret.txt",
            files[0].DisplayPath);
        Assert.AreEqual($"huggingface-{resourceName}", files[0].ProvenanceType);
        Assert.AreEqual("hf-secret-1", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/revision/main", string.Join('\n', requests));
        Assert.Contains("/tree/abc123?recursive=true&expand=true", string.Join('\n', requests));
        Assert.Contains("/resolve/abc123/config/secret.txt", string.Join('\n', requests));
        Assert.DoesNotContain("config%2Fsecret.txt", string.Join('\n', requests));
    }

    /// <summary>
    /// Verifies that pull-request scans resolve the pull-request ref and include its discussion diff.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryIncludesSelectedPullRequest()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            requests.Add(uri);
            if (uri.Contains("/revision/refs%2Fpr%2F7", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse("""{"sha":"prcommit"}""");
            }

            if (uri.Contains("/tree/prcommit", StringComparison.Ordinal))
            {
                return JsonResponse("[]");
            }

            if (uri.Contains("/discussions/7?diff=1", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "title": "Update configuration",
                      "num": 7,
                      "status": "open",
                      "author": {"name": "contributor"},
                      "isPullRequest": true,
                      "events": [],
                      "diff": "+token=hf_pull_request_secret"
                    }
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            pullRequestNumber: 7);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual(
            "huggingface/model/owner/project/prcommit/pull-requests/7.md",
            files[0].DisplayPath);
        Assert.Contains("hf_pull_request_secret", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.DoesNotContain("type=discussion", string.Join('\n', requests));
    }

    /// <summary>
    /// Verifies that discussion enumeration follows bounded API pages and emits synthetic Markdown.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryIncludesDiscussions()
    {
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"discussioncommit"}""");
            }

            if (uri.Contains("/tree/discussioncommit", StringComparison.Ordinal))
            {
                return JsonResponse("[]");
            }

            if (uri.Contains("/discussions?p=0", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "count": 2,
                      "start": 0,
                      "discussions": [{"num": 11, "isPullRequest": false}]
                    }
                    """);
            }

            if (uri.Contains("/discussions?p=1", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "count": 2,
                      "start": 1,
                      "discussions": [{"num": 12, "isPullRequest": false}]
                    }
                    """);
            }

            if (uri.Contains("/discussions/11?", StringComparison.Ordinal))
            {
                return DiscussionResponse(11, "hf_discussion_secret_11");
            }

            if (uri.Contains("/discussions/12?", StringComparison.Ordinal))
            {
                return DiscussionResponse(12, "hf_discussion_secret_12");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Dataset,
            "owner/data",
            "token",
            includeDiscussions: true);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, files);
        Assert.AreEqual(
            "huggingface/dataset/owner/data/discussioncommit/discussions/11.md",
            files[0].DisplayPath);
        Assert.Contains("hf_discussion_secret_11", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("hf_discussion_secret_12", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
    }

    /// <summary>
    /// Verifies that bucket object paths carry their Xet content identity and selected prefix.
    /// </summary>
    [TestMethod]
    public async Task EnumerateBucketUsesXetContentIdentity()
    {
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            requests.Add(uri);
            if (uri.Contains("/api/buckets/owner/secrets/tree/config%2Fprod", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse(
                    """[{"type":"file","path":"config/prod/app.env","size":16,"xetHash":"xet123"}]""");
            }

            if (uri.Contains("/buckets/owner/secrets/resolve/config%2Fprod%2Fapp.env", StringComparison.OrdinalIgnoreCase))
            {
                return BytesResponse("hf_bucket_secret");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Bucket,
            "owner/secrets",
            "token",
            bucketPrefix: "config/prod");

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual(
            "huggingface/bucket/owner/secrets/xet123/config/prod/app.env",
            files[0].DisplayPath);
        Assert.AreEqual("huggingface-bucket", files[0].ProvenanceType);
        Assert.Contains("?recursive=true", requests[0]);
    }

    /// <summary>
    /// Verifies that redirected downloads omit the Hugging Face token.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryDoesNotForwardCredentialAcrossRedirect()
    {
        const string Token = "hf-private-token";
        var requests = new List<string>();
        var authorization = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            requests.Add(uri);
            authorization.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"large.bin","size":12}]""");
            }

            if (uri.Contains("/resolve/abc123/", StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.hf.co/blob/large.bin?signature=opaque");
            }

            if (uri.Equals("https://cdn.hf.co/blob/large.bin?signature=opaque", StringComparison.Ordinal))
            {
                return BytesResponse("hf-lfs-token");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Model,
            "owner/project",
            Token);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        int redirectedRequest = requests.IndexOf("https://cdn.hf.co/blob/large.bin?signature=opaque");
        Assert.HasCount(1, files);
        Assert.AreNotEqual(-1, redirectedRequest);
        Assert.AreEqual(string.Empty, authorization[redirectedRequest]);
        Assert.Contains($"Bearer {Token}", authorization);
        Assert.DoesNotContain(Token, string.Join('\n', requests));
    }

    /// <summary>
    /// Verifies that repository downloads reject redirects which downgrade HTTPS to HTTP.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryRejectsInsecureDownloadRedirect()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"large.bin","size":12}]""");
            }

            return RedirectResponse("http://cdn.hf.co/blob/large.bin");
        });
        using var httpClient = new HttpClient(handler);
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(3, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("redirected download URL is not allowed", warnings[0]);
    }

    /// <summary>
    /// Verifies that responses from handlers which already followed a download redirect are rejected.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryBlocksAutoFollowedDownloadRedirect()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"large.bin","size":12}]""");
            }

            return AutoRedirectedBytesResponse("hf-lfs-token", "https://cdn.hf.co/blob/large.bin");
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("returned 421", warnings[0]);
    }

    /// <summary>
    /// Verifies that a second download redirect is rejected.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryDoesNotFollowSecondRedirect()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"large.bin","size":12}]""");
            }

            if (uri.Contains("/resolve/abc123/", StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.hf.co/blob/large.bin");
            }

            return RedirectResponse("https://cdn.hf.co/blob/again.bin");
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("required more than one redirect", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that redirected repository downloads remain subject to the streaming byte cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryAppliesStreamingByteCapAfterRedirect()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"large.bin","size":1}]""");
            }

            if (uri.Contains("/resolve/abc123/", StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.hf.co/blob/large.bin");
            }

            HttpResponseMessage response = BytesResponse("0123456789");
            response.Content.Headers.ContentLength = 1;
            return response;
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            maxFileBytes: 4,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("file byte limit skipped", warnings[0]);
    }

    /// <summary>
    /// Verifies that repository downloads enforce the byte cap against bytes read.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryAppliesStreamingByteCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"secret.txt","size":1}]""");
            }

            HttpResponseMessage response = BytesResponse("0123456789");
            response.Content.Headers.ContentLength = 1;
            return response;
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            maxFileBytes: 4,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("file byte limit skipped", warnings[0]);
    }

    /// <summary>
    /// Verifies that repository archives are expanded through the shared bounded archive reader.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryExpandsArchives()
    {
        byte[] archive = CreateZipBytes("nested/secret.txt", "hf_archive_secret");
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse(
                    string.Create(
                        System.Globalization.CultureInfo.InvariantCulture,
                        $"[{{\"type\":\"file\",\"path\":\"bundle.zip\",\"size\":{archive.Length}}}]"));
            }

            return BytesResponse(archive);
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Space,
            "owner/app",
            "token");

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual(
            "huggingface/space/owner/app/abc123/bundle.zip!nested/secret.txt",
            files[0].DisplayPath);
        Assert.AreEqual("hf_archive_secret", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("huggingface-space", files[0].ProvenanceType);
    }

    /// <summary>
    /// Verifies that malformed metadata becomes a non-fatal warning without exposing credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryHandlesMalformedMetadata()
    {
        const string Token = "hf-sensitive-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => JsonResponse("{")));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("JSON parsing failed", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that metadata pagination cannot leave the configured Hugging Face endpoint.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryRejectsExternalMetadataPagination()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            HttpResponseMessage response = JsonResponse("[]");
            response.Headers.Add(
                "Link",
                "<https://attacker.example/api/models/owner/project/tree/abc123?page=2>; rel=\"next\"");
            return response;
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("next-page URL is not allowed", warnings[0]);
    }

    /// <summary>
    /// Verifies that provider-controlled repository paths cannot alter download URL routing.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryRejectsUnsafeFilePath()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            if (uri.Contains("/tree/abc123", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"file","path":"config/../secret.txt","size":12}]""");
            }

            throw new AssertFailedException("An unsafe file path must not be downloaded.");
        });
        using var httpClient = new HttpClient(handler);
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("path contains unsafe segments", warnings[0]);
    }

    /// <summary>
    /// Verifies that repository tree enumeration stops at the pagination safety limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryStopsAtPaginationSafetyLimit()
    {
        var warnings = new List<string>();
        int treeRequests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string uri = request.RequestUri!.AbsoluteUri;
            if (uri.Contains("/revision/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"sha":"abc123"}""");
            }

            treeRequests++;
            HttpResponseMessage response = JsonResponse("[]");
            response.Headers.Add(
                "Link",
                $"</api/models/owner/project/tree/abc123?page={treeRequests + 1}>; rel=\"next\"");
            return response;
        }));
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1000, treeRequests);
        Assert.HasCount(1, warnings);
        Assert.Contains("pagination safety limit", warnings[0]);
    }

    /// <summary>
    /// Verifies that callback cancellation prevents any remote requests.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryHonorsCancellationCallback()
    {
        var handler = new FakeHttpMessageHandler(static _ => throw new AssertFailedException("No request was expected."));
        using var httpClient = new HttpClient(handler);
        var client = new HuggingFaceSourceClient(httpClient);
        var options = new HuggingFaceSourceOptions(
            new Uri("https://hub.example.test/", UriKind.Absolute),
            HuggingFaceResourceKind.Model,
            "owner/project",
            "token",
            isCancellationRequested: static () => true);

        List<SourceFile> files = await client.EnumerateAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(0, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that bucket selectors reject repository-only settings.
    /// </summary>
    [TestMethod]
    public void OptionsRejectRepositoryFeaturesForBuckets()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Bucket,
            "owner/bucket",
            "token",
            revision: "main"));
        Assert.ThrowsExactly<ArgumentException>(() => new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Bucket,
            "owner/bucket",
            "token",
            pullRequestNumber: 1));
        Assert.ThrowsExactly<ArgumentException>(() => new HuggingFaceSourceOptions(
            HuggingFaceSourceOptions.CreateDefaultEndpoint(),
            HuggingFaceResourceKind.Bucket,
            "owner/bucket",
            "token",
            includeDiscussions: true));
    }

    private static HttpResponseMessage DiscussionResponse(int number, string content)
    {
        return JsonResponse(
            $$$"""
              {
                "title": "Discussion {{{number}}}",
                "num": {{{number}}},
                "status": "open",
                "author": {"name": "author"},
                "isPullRequest": false,
                "events": [
                  {
                    "type": "comment",
                    "author": {"name": "commenter"},
                    "data": {"latest": {"raw": "{{{content}}}"}}
                  }
                ]
              }
              """);
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
        return BytesResponse(Encoding.UTF8.GetBytes(text));
    }

    private static HttpResponseMessage BytesResponse(byte[] bytes)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes),
        };
    }

    private static HttpResponseMessage AutoRedirectedBytesResponse(string content, string redirectedUri)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content)),
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, redirectedUri),
        };
    }

    private static HttpResponseMessage RedirectResponse(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(location, UriKind.Absolute);
        return response;
    }

    private static byte[] CreateZipBytes(string entryName, string content)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using Stream entryStream = entry.Open();
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            entryStream.Write(bytes);
        }

        return stream.ToArray();
    }
}
