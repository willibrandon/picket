using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Bitbucket source enumeration.
/// </summary>
[TestClass]
public sealed class BitbucketSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Bitbucket repository source options reject ambiguous ref and pull request scopes.
    /// </summary>
    [TestMethod]
    public void BitbucketSourceOptionsRejectsRefAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new BitbucketSourceOptions(
            BitbucketSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "bitbucket-test-token",
            gitRef: "main",
            pullRequestId: 7));

        Assert.Contains("either a ref or a pull request ID", ex.Message);
    }

    /// <summary>
    /// Verifies that Bitbucket repository source options reject pull request scans combined with download artifact enumeration.
    /// </summary>
    [TestMethod]
    public void BitbucketSourceOptionsRejectsPullRequestAndDownloads()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new BitbucketSourceOptions(
            BitbucketSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "bitbucket-test-token",
            pullRequestId: 7,
            includeDownloads: true));

        Assert.Contains("cannot combine pull request scans with download artifact enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that pull request enumeration resolves the source repository and commit before reading source files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsPullRequestSourceRepository()
    {
        const string Token = "bitbucket-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repositories/willibrandon/picket/pullrequests/7", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "id": 7,
                      "source": {
                        "branch": {
                          "name": "feature/secrets"
                        },
                        "commit": {
                          "hash": "pr-head-sha"
                        },
                        "repository": {
                          "full_name": "forkspace/picket-fork"
                        }
                      }
                    }
                    """);
            }

            if (url.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"pagelen":100,"page":1,"size":1,"values":[{"path":"src","type":"commit_directory"}]}""");
            }

            if (url.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/src/?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"pagelen":100,"page":1,"size":1,"values":[{"path":"src/pr.txt","type":"commit_file","size":14}]}""");
            }

            if (url.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/src/pr.txt", StringComparison.Ordinal))
            {
                return BytesResponse("pr-token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketSourceClient(httpClient);
        var options = new BitbucketSourceOptions(
            BitbucketSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            pullRequestId: 7);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("bitbucket/forkspace/picket-fork/src/pr.txt", files[0].DisplayPath);
        Assert.AreEqual("pr-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/repositories/willibrandon/picket/pullrequests/7", requests);
        Assert.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/?", requests);
        Assert.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/src/?", requests);
        Assert.Contains("/repositories/forkspace/picket-fork/src/pr-head-sha/src/pr.txt", requests);
        Assert.DoesNotContain("/repositories/willibrandon/picket/src/", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that repository download artifacts are enumerated and expanded through the archive reader.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsDownloadArtifacts()
    {
        const string Token = "bitbucket-test-token";
        byte[] archiveBytes = CreateZipBytes("nested/secret.txt", "artifact-token-12345");
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);

            if (url.Contains("/repositories/willibrandon/picket/src/main/?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"pagelen":100,"page":1,"size":0,"values":[]}""");
            }

            if (url.Contains("/repositories/willibrandon/picket/downloads?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "pagelen": 100,
                      "page": 1,
                      "size": 1,
                      "values": [
                        {
                          "name": "build.zip",
                          "size": 160,
                          "links": {
                            "self": {
                              "href": "https://api.bitbucket.org/2.0/repositories/willibrandon/picket/downloads/build.zip"
                            }
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/repositories/willibrandon/picket/downloads/build.zip", StringComparison.Ordinal))
            {
                return RedirectResponse("https://downloads.bitbucket.org/willibrandon/picket/build.zip?signature=abc");
            }

            if (url.Equals("https://downloads.bitbucket.org/willibrandon/picket/build.zip?signature=abc", StringComparison.Ordinal))
            {
                return BytesResponse(archiveBytes);
            }

            if (url.Contains("/repositories/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"mainbranch":{"name":"main"}}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new BitbucketSourceClient(httpClient);
        var options = new BitbucketSourceOptions(
            BitbucketSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeDownloads: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        int redirectedRequestIndex = urls.IndexOf("https://downloads.bitbucket.org/willibrandon/picket/build.zip?signature=abc");
        Assert.HasCount(1, files);
        Assert.AreEqual("bitbucket/willibrandon/picket/downloads/build.zip!nested/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreNotEqual(-1, redirectedRequestIndex);
        Assert.Contains("/repositories/willibrandon/picket/downloads?pagelen=100&page=1", requests);
        Assert.Contains("/repositories/willibrandon/picket/downloads/build.zip", requests);
        Assert.Contains("Bearer bitbucket-test-token", authorizationHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[redirectedRequestIndex]);
        Assert.DoesNotContain(Token, requests);
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

    private static HttpResponseMessage BytesResponse(byte[] content)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(content),
        };
    }

    private static HttpResponseMessage RedirectResponse(string location)
    {
        return new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            Headers =
            {
                Location = new Uri(location, UriKind.Absolute),
            },
        };
    }

    private static byte[] CreateZipBytes(string entryName, string entryContent)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using Stream entryStream = entry.Open();
            byte[] bytes = Encoding.UTF8.GetBytes(entryContent);
            entryStream.Write(bytes);
        }

        return stream.ToArray();
    }
}
