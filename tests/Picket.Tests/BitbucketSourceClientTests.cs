using Picket.Sources;
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
