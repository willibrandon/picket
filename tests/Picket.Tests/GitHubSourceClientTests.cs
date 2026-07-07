using Picket.Sources;
using System.Net;
using System.Text;

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
    /// Verifies that GitHub repository source options reject ambiguous ref and pull request scopes.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsRefAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            "main",
            pullRequestNumber: 42));

        Assert.Contains("either a ref or a pull request number", ex.Message);
    }

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
    /// Verifies that pull request enumeration resolves the head repository and SHA before reading source files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsPullRequestHeadRepository()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repos/willibrandon/picket/pulls/42", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "number": 42,
                      "head": {
                        "sha": "abcdef1234567890",
                        "repo": {
                          "full_name": "forker/picket-fork"
                        }
                      }
                    }
                    """);
            }

            if (url.Contains("/repos/forker/picket-fork/git/trees/abcdef1234567890?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"src/pr.txt","type":"blob","size":14}]}""");
            }

            if (url.Contains("/repos/forker/picket-fork/contents/src/pr.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("pr-token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            pullRequestNumber: 42);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("github/forker/picket-fork/src/pr.txt", files[0].DisplayPath);
        Assert.AreEqual("pr-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/repos/willibrandon/picket/pulls/42", requests);
        Assert.Contains("/repos/forker/picket-fork/git/trees/abcdef1234567890?", requests);
        Assert.Contains("ref=abcdef1234567890", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/git/trees/", requests);
        Assert.DoesNotContain(Token, requests);
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

    /// <summary>
    /// Verifies that organization enumeration follows paged repositories and scans each default branch.
    /// </summary>
    [TestMethod]
    public async Task EnumerateOrganizationRepositoryFilesFollowsRepositoryPages()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/orgs/willibrandon/repos?", StringComparison.Ordinal)
                && url.Contains("&page=1", StringComparison.Ordinal))
            {
                HttpResponseMessage response = JsonResponse("""[{"name":"one","default_branch":"main"}]""");
                response.Headers.Add("Link", "<https://api.github.com/orgs/willibrandon/repos?type=sources&per_page=100&page=2>; rel=\"next\"");
                return response;
            }

            if (url.Contains("/orgs/willibrandon/repos?", StringComparison.Ordinal)
                && url.Contains("&page=2", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"name":"two","default_branch":"trunk"}]""");
            }

            if (url.Contains("/repos/willibrandon/one/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"one.txt","type":"blob","size":9}]}""");
            }

            if (url.Contains("/repos/willibrandon/two/git/trees/trunk?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"two.txt","type":"blob","size":9}]}""");
            }

            if (url.Contains("/repos/willibrandon/one/contents/one.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-111");
            }

            if (url.Contains("/repos/willibrandon/two/contents/two.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-222");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubOrganizationSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            Token,
            repositoryType: "sources");

        List<SourceFile> files = await client.EnumerateOrganizationRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, files);
        Assert.AreEqual("github/willibrandon/one/one.txt", files[0].DisplayPath);
        Assert.AreEqual("github/willibrandon/two/two.txt", files[1].DisplayPath);
        Assert.Contains("type=sources", string.Join('\n', urls));
        Assert.Contains("per_page=100", string.Join('\n', urls));
        Assert.Contains("page=2", string.Join('\n', urls));
        Assert.DoesNotContain(Token, string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that organization enumeration warns and continues when one repository cannot be scanned.
    /// </summary>
    [TestMethod]
    public async Task EnumerateOrganizationRepositoryFilesSkipsRepositoryFailures()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/orgs/willibrandon/repos?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {"name":"empty","default_branch":""},
                      {"name":"denied","default_branch":"main"},
                      {"name":"readable","default_branch":"main"}
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/denied/git/trees/main?", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Forbidden);
            }

            if (url.Contains("/repos/willibrandon/readable/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"ok.txt","type":"blob","size":9}]}""");
            }

            if (url.Contains("/repos/willibrandon/readable/contents/ok.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-333");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubOrganizationSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateOrganizationRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("github/willibrandon/readable/ok.txt", files[0].DisplayPath);
        Assert.HasCount(2, warnings);
        Assert.Contains("skipping GitHub repository willibrandon/empty because it does not have a default branch", warnings[0]);
        Assert.Contains("skipping GitHub repository willibrandon/denied", warnings[1]);
        Assert.Contains("403 Forbidden", warnings[1]);
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
