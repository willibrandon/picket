using Picket.Sources;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Gitea source enumeration.
/// </summary>
[TestClass]
public sealed class GiteaSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Gitea repository source options reject ambiguous ref and pull request scopes.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsRefAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            "main",
            pullRequestId: 7));

        Assert.Contains("either a ref or a pull request ID", ex.Message);
    }

    /// <summary>
    /// Verifies that Gitea repository source options reject ambiguous pull request and issue scopes.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsPullRequestAndIssues()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            includeIssues: true,
            pullRequestId: 7));

        Assert.Contains("cannot combine pull request and issue enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that Gitea repository source options reject ambiguous pull request and release scopes.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsPullRequestAndReleases()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            pullRequestId: 7,
            includeReleases: true));

        Assert.Contains("cannot combine pull request and release enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that Gitea repository source options reject unknown issue states.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsInvalidIssueState()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            includeIssues: true,
            issueState: "triaged"));

        Assert.Contains("open, closed, or all", ex.Message);
    }

    /// <summary>
    /// Verifies that pull request enumeration resolves the source repository and commit before reading source files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsPullRequestSourceRepository()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repos/willibrandon/picket/pulls/7", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "number": 7,
                      "head": {
                        "sha": "pr-head-sha",
                        "ref": "feature/secrets",
                        "repo": {
                          "full_name": "forker/picket-fork"
                        }
                      }
                    }
                    """);
            }

            if (url.Contains("/repos/forker/picket-fork/branches/pr-head-sha", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (url.Contains("/repos/forker/picket-fork/git/trees/pr-head-sha?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"src/pr.txt","type":"blob","size":14}],"truncated":false,"page":1,"total_count":1}""");
            }

            if (url.Contains("/repos/forker/picket-fork/raw/src/pr.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("pr-token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            pullRequestId: 7);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitea/forker/picket-fork/src/pr.txt", files[0].DisplayPath);
        Assert.AreEqual("pr-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/repos/willibrandon/picket/pulls/7", requests);
        Assert.Contains("/repos/forker/picket-fork/git/trees/pr-head-sha?", requests);
        Assert.Contains("/repos/forker/picket-fork/raw/src/pr.txt?", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/git/trees/", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that organization enumeration lists repositories and scans each repository default branch.
    /// </summary>
    [TestMethod]
    public async Task EnumerateOrganizationRepositoryFilesReadsRepositoryFiles()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/orgs/acme/repos?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "full_name": "acme/alpha",
                        "name": "alpha",
                        "default_branch": "main"
                      },
                      {
                        "name": "beta",
                        "owner": { "login": "acme" },
                        "default_branch": "trunk"
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/acme/alpha/branches/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"main","commit":{"id":"alpha-sha"}}""");
            }

            if (url.Contains("/repos/acme/beta/branches/trunk", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"trunk","commit":{"id":"beta-sha"}}""");
            }

            if (url.Contains("/repos/acme/alpha/git/trees/alpha-sha?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"alpha.txt","type":"blob","size":15}],"truncated":false,"page":1,"total_count":1}""");
            }

            if (url.Contains("/repos/acme/beta/git/trees/beta-sha?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"beta.txt","type":"blob","size":14}],"truncated":false,"page":1,"total_count":1}""");
            }

            if (url.Contains("/repos/acme/alpha/raw/alpha.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("alpha-token-111");
            }

            if (url.Contains("/repos/acme/beta/raw/beta.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("beta-token-222");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaOrganizationSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "acme",
            Token);

        List<SourceFile> files = await client.EnumerateOrganizationRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("gitea/acme/alpha/alpha.txt", files[0].DisplayPath);
        Assert.AreEqual("alpha-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("gitea/acme/beta/beta.txt", files[1].DisplayPath);
        Assert.AreEqual("beta-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/orgs/acme/repos?page=1&limit=100", requests);
        Assert.Contains("/repos/acme/alpha/git/trees/alpha-sha?", requests);
        Assert.Contains("/repos/acme/beta/git/trees/beta-sha?", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that user enumeration lists repositories and uses the explicit ref when supplied.
    /// </summary>
    [TestMethod]
    public async Task EnumerateUserRepositoryFilesReadsRepositoriesAtExplicitRef()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/users/octo/repos?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "name": "alpha",
                        "owner": { "username": "octo" },
                        "default_branch": "main"
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/octo/alpha/branches/release", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"release","commit":{"id":"release-sha"}}""");
            }

            if (url.Contains("/repos/octo/alpha/git/trees/release-sha?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"release.txt","type":"blob","size":17}],"truncated":false,"page":1,"total_count":1}""");
            }

            if (url.Contains("/repos/octo/alpha/raw/release.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("release-token-333");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaUserSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "octo",
            Token,
            "release");

        List<SourceFile> files = await client.EnumerateUserRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitea/octo/alpha/release.txt", files[0].DisplayPath);
        Assert.AreEqual("release-token-333", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/users/octo/repos?page=1&limit=100", requests);
        Assert.Contains("/repos/octo/alpha/branches/release", requests);
        Assert.DoesNotContain("/repos/octo/alpha/branches/main", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that release enumeration reads release notes and assets without forwarding the token to asset downloads.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsReleasesAndAssetsWithoutAuthorization()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            authorizationHeaders.Add(request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values) ? string.Join(',', values) : string.Empty);
            if (url.Contains("/repos/willibrandon/picket/branches/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"main","commit":{"id":"abcdef1234567890"}}""");
            }

            if (url.Contains("/repos/willibrandon/picket/git/trees/abcdef1234567890?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[],"truncated":false,"page":1,"total_count":0}""");
            }

            if (url.Contains("/repos/willibrandon/picket/releases?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 100,
                        "tag_name": "v1.0.0",
                        "name": "Release token-111",
                        "body": "body-token-111",
                        "assets": [
                          {
                            "id": 501,
                            "name": "artifact.txt",
                            "size": 15,
                            "browser_download_url": "https://gitea.example/downloads/artifact.txt"
                          }
                        ]
                      }
                    ]
                    """);
            }

            if (url.Equals("https://gitea.example/downloads/artifact.txt", StringComparison.Ordinal))
            {
                return BytesResponse("asset-token-222");
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main","empty":false}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaSourceOptions(
            new Uri("https://gitea.example/api/v1/", UriKind.Absolute),
            "willibrandon/picket",
            Token,
            includeReleases: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        int assetRequestIndex = urls.IndexOf("https://gitea.example/downloads/artifact.txt");
        Assert.HasCount(2, files);
        Assert.AreEqual("gitea/willibrandon/picket/releases/v1.0.0.md", files[0].DisplayPath);
        Assert.Contains("Release token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("body-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("gitea/willibrandon/picket/releases/v1.0.0/assets/artifact.txt", files[1].DisplayPath);
        Assert.AreEqual("asset-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/repos/willibrandon/picket/releases?page=1&limit=100", requests);
        Assert.AreNotEqual(-1, assetRequestIndex);
        Assert.Contains("token gitea-test-token", authorizationHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[assetRequestIndex]);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that release enumeration does not fetch arbitrary asset URLs returned by the Gitea API.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsUnexpectedReleaseAssetHosts()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repos/willibrandon/picket/branches/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"main","commit":{"id":"abcdef1234567890"}}""");
            }

            if (url.Contains("/repos/willibrandon/picket/git/trees/abcdef1234567890?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[],"truncated":false,"page":1,"total_count":0}""");
            }

            if (url.Contains("/repos/willibrandon/picket/releases?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 100,
                        "tag_name": "v1.0.0",
                        "body": "body-token-111",
                        "assets": [
                          {
                            "name": "artifact.txt",
                            "size": 15,
                            "browser_download_url": "https://other.example/downloads/artifact.txt"
                          }
                        ]
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main","empty":false}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaSourceOptions(
            new Uri("https://gitea.example/api/v1/", UriKind.Absolute),
            "willibrandon/picket",
            Token,
            warningSink: warnings.Add,
            includeReleases: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitea/willibrandon/picket/releases/v1.0.0.md", files[0].DisplayPath);
        Assert.DoesNotContain("https://other.example/downloads/artifact.txt", requests);
        Assert.Contains("not an allowed Gitea asset endpoint", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that issue enumeration reads issue bodies and comments while skipping pull request issues.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsIssuesAndComments()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repos/willibrandon/picket/branches/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"main","commit":{"id":"abcdef1234567890"}}""");
            }

            if (url.Contains("/repos/willibrandon/picket/git/trees/abcdef1234567890?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[],"truncated":false,"page":1,"total_count":0}""");
            }

            if (url.Contains("/repos/willibrandon/picket/issues/comments?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 99,
                        "issue_url": "https://gitea.com/api/v1/repos/willibrandon/picket/issues/7",
                        "body": "comment-token-222"
                      },
                      {
                        "id": 100,
                        "issue_url": "https://gitea.com/api/v1/repos/willibrandon/picket/issues/8",
                        "body": "skip-token-999"
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket/issues?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "number": 7,
                        "title": "leaked issue-token-111",
                        "body": "body-token-111",
                        "comments": 1
                      },
                      {
                        "number": 8,
                        "title": "pull request token-999",
                        "body": "skip-token-999",
                        "comments": 1,
                        "pull_request": {
                          "url": "https://gitea.com/api/v1/repos/willibrandon/picket/pulls/8"
                        }
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main","empty":false}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeIssues: true,
            issueState: "closed");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("gitea/willibrandon/picket/issues/7.md", files[0].DisplayPath);
        Assert.Contains("leaked issue-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("body-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("gitea/willibrandon/picket/issues/7/comments/99.md", files[1].DisplayPath);
        Assert.Contains("comment-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("state=closed", requests);
        Assert.Contains("type=issues", requests);
        Assert.Contains("limit=100", requests);
        Assert.Contains("/repos/willibrandon/picket/issues/comments?", requests);
        Assert.DoesNotContain("skip-token-999", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
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
