using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
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
    /// Verifies that GitHub repository source options reject ambiguous issue and pull request scopes.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsIssuesAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            pullRequestNumber: 42,
            includeIssues: true));

        Assert.Contains("either issue enumeration or a pull request number", ex.Message);
    }

    /// <summary>
    /// Verifies that GitHub repository source options reject ambiguous release and pull request scopes.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsReleasesAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            pullRequestNumber: 42,
            includeReleases: true));

        Assert.Contains("either release enumeration or a pull request number", ex.Message);
    }

    /// <summary>
    /// Verifies that GitHub repository source options reject ambiguous Actions artifact and pull request scopes.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsActionsArtifactsAndPullRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            pullRequestNumber: 42,
            includeActionArtifacts: true));

        Assert.Contains("either Actions artifact enumeration or a pull request number", ex.Message);
    }

    /// <summary>
    /// Verifies that GitHub repository source options reject invalid issue states.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsInvalidIssueState()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            includeIssues: true,
            issueState: "merged"));

        Assert.Contains("GitHub issue state must be one of", ex.Message);
    }

    /// <summary>
    /// Verifies that GitHub user source options reject invalid repository type filters.
    /// </summary>
    [TestMethod]
    public void GitHubUserSourceOptionsRejectsInvalidRepositoryType()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitHubUserSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            "github-test-token",
            repositoryType: "public"));

        Assert.Contains("GitHub user repository type must be one of", ex.Message);
    }

    /// <summary>
    /// Verifies that GitHub source options default to bounded remote downloads.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsDefaultsToBoundedRemoteDownloads()
    {
        var repositoryOptions = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token");
        var organizationOptions = new GitHubOrganizationSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            "github-test-token");
        var userOptions = new GitHubUserSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            "github-test-token");
        var gistOptions = new GitHubGistSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "github-test-token",
            "gist-one");

        Assert.AreEqual(100_000_000, repositoryOptions.MaxFileBytes);
        Assert.AreEqual(100_000_000, organizationOptions.MaxFileBytes);
        Assert.AreEqual(100_000_000, userOptions.MaxFileBytes);
        Assert.AreEqual(100_000_000, gistOptions.MaxFileBytes);
    }

    /// <summary>
    /// Verifies that GitHub source options reject unbounded remote downloads.
    /// </summary>
    [TestMethod]
    public void GitHubSourceOptionsRejectsZeroForUnboundedRemoteDownloads()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "github-test-token",
            maxFileBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GitHubOrganizationSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            "github-test-token",
            maxFileBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GitHubUserSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            "github-test-token",
            maxFileBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new GitHubGistSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "github-test-token",
            "gist-one",
            maxFileBytes: 0));
    }

    /// <summary>
    /// Verifies that GitHub gist source options reject ambiguous selectors.
    /// </summary>
    [TestMethod]
    public void GitHubGistSourceOptionsRejectsAmbiguousSelectors()
    {
        var options = new GitHubGistSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "github-test-token",
            "gist-one",
            includeAuthenticatedGists: true);

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(options.ValidateSelector);

        Assert.Contains("exactly one", ex.Message);
    }

    /// <summary>
    /// Verifies that oversized repository metadata responses are skipped instead of parsed.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsOversizedMetadataResponse()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ => OversizedJsonMetadataResponse()));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("remote metadata response reported 10000001 bytes", warnings[0]);
        Assert.Contains("metadata cap", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that oversized streaming metadata responses are capped even when no content length is available.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsOversizedStreamingMetadataResponse()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ => OversizedStreamingJsonMetadataResponse()));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("GitHub source metadata", warnings[0]);
        Assert.Contains("remote metadata response exceeded the 10000000 byte metadata cap", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
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
    /// Verifies that issue enumeration reads issue bodies and comments while skipping pull request issues.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsIssuesAndComments()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/repos/willibrandon/picket/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[]}""");
            }

            if (url.Contains("/repos/willibrandon/picket/issues/7/comments?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"id":99,"body":"comment-token-222"}]""");
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
                          "url": "https://api.github.com/repos/willibrandon/picket/pulls/8"
                        }
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeIssues: true,
            issueState: "closed");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("github/willibrandon/picket/issues/7.md", files[0].DisplayPath);
        Assert.Contains("leaked issue-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("body-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("github/willibrandon/picket/issues/7/comments/99.md", files[1].DisplayPath);
        Assert.Contains("comment-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("state=closed", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("/repos/willibrandon/picket/issues/7/comments?", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/issues/8/comments?", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that gist enumeration reads gist files, raw fallback content, and comments.
    /// </summary>
    [TestMethod]
    public async Task EnumerateGistFilesReadsFilesRawFallbackAndComments()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            if (url.Contains("/gists/gist-one/comments?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"id":77,"body":"comment-token-333"}]""");
            }

            if (url.Contains("/raw/gists/gist-one/raw.txt", StringComparison.Ordinal))
            {
                return BytesResponse("raw-token-222");
            }

            if (url.Contains("/gists/gist-one", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "id": "gist-one",
                      "owner": { "login": "octocat" },
                      "comments": 1,
                      "files": {
                        "secret.txt": {
                          "filename": "secret.txt",
                          "size": 15,
                          "truncated": false,
                          "content": "file-token-111"
                        },
                        "raw.txt": {
                          "filename": "raw.txt",
                          "size": 13,
                          "truncated": true,
                          "raw_url": "https://api.github.com/raw/gists/gist-one/raw.txt"
                        }
                      }
                    }
                    """);
            }

            if (url.Contains("/gists?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"id":"gist-one"}]""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubGistSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            Token,
            includeAuthenticatedGists: true);

        List<SourceFile> files = await client.EnumerateGistFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(3, files);
        Assert.AreEqual("github/gists/octocat/gist-one/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("file-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("github/gists/octocat/gist-one/raw.txt", files[1].DisplayPath);
        Assert.AreEqual("raw-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.AreEqual("github/gists/octocat/gist-one/comments/77.md", files[2].DisplayPath);
        Assert.Contains("comment-token-333", Encoding.UTF8.GetString(files[2].ReadAllBytes()));
        Assert.Contains("/gists?per_page=100", requests);
        Assert.Contains("/gists/gist-one", requests);
        Assert.Contains("/gists/gist-one/comments?", requests);
        Assert.Contains("/raw/gists/gist-one/raw.txt", requests);
        Assert.Contains("Bearer github-test-token", authorizationHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[2]);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that release enumeration reads release notes and release asset content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsReleasesAndAssets()
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
                return JsonResponse("""{"tree":[]}""");
            }

            if (url.Contains("/repos/willibrandon/picket/releases/assets/501", StringComparison.Ordinal))
            {
                return BytesResponse("asset-token-222");
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
                            "url": "https://api.github.com/repos/willibrandon/picket/releases/assets/501"
                          }
                        ]
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeReleases: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("github/willibrandon/picket/releases/v1.0.0.md", files[0].DisplayPath);
        Assert.Contains("Release token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("body-token-111", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("github/willibrandon/picket/releases/v1.0.0/assets/artifact.txt", files[1].DisplayPath);
        Assert.AreEqual("asset-token-222", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/repos/willibrandon/picket/releases?per_page=100", requests);
        Assert.Contains("/repos/willibrandon/picket/releases/assets/501", requests);
        Assert.Contains("Bearer github-test-token", authorizationHeaders);
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that release asset redirects are downloaded without forwarding the GitHub token.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsRedirectedReleaseAssetsWithoutAuthorization()
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
                return JsonResponse("""{"tree":[]}""");
            }

            if (url.Contains("/repos/willibrandon/picket/releases/assets/501", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Found)
                {
                    Headers =
                    {
                        Location = new Uri("https://objects.githubusercontent.com/release-assets/artifact.txt"),
                    },
                };
            }

            if (url.Equals("https://objects.githubusercontent.com/release-assets/artifact.txt", StringComparison.Ordinal))
            {
                return BytesResponse("redirect-token-333");
            }

            if (url.Contains("/repos/willibrandon/picket/releases?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 100,
                        "tag_name": "v1.0.0",
                        "assets": [
                          {
                            "id": 501,
                            "name": "artifact.txt",
                            "size": 18,
                            "url": "https://api.github.com/repos/willibrandon/picket/releases/assets/501"
                          }
                        ]
                      }
                    ]
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeReleases: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        int redirectedRequestIndex = urls.IndexOf("https://objects.githubusercontent.com/release-assets/artifact.txt");
        Assert.HasCount(2, files);
        Assert.AreEqual("github/willibrandon/picket/releases/v1.0.0/assets/artifact.txt", files[1].DisplayPath);
        Assert.AreEqual("redirect-token-333", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.AreNotEqual(-1, redirectedRequestIndex);
        Assert.Contains("/repos/willibrandon/picket/releases/assets/501", requests);
        Assert.Contains("Bearer github-test-token", authorizationHeaders);
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[redirectedRequestIndex]);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that Actions artifact enumeration reads ZIP entries and follows redirects without forwarding the GitHub token.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsActionsArtifacts()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        var acceptHeaders = new List<string>();
        byte[] archiveBytes = CreateZipBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("artifact-token-444")));
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            CaptureRequest(request, urls, authorizationHeaders, acceptHeaders);
            string url = request.RequestUri!.ToString();
            if (url.Contains("/repos/willibrandon/picket/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[]}""");
            }

            if (url.Contains("/repos/willibrandon/picket/actions/artifacts/701/zip", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Found)
                {
                    Headers =
                    {
                        Location = new Uri("https://productionresultssa1.blob.core.windows.net/actions-results/artifact.zip"),
                    },
                };
            }

            if (url.Equals("https://productionresultssa1.blob.core.windows.net/actions-results/artifact.zip", StringComparison.Ordinal))
            {
                return BytesResponse(archiveBytes);
            }

            if (url.Contains("/repos/willibrandon/picket/actions/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "total_count": 1,
                      "artifacts": [
                        {
                          "id": 701,
                          "name": "build",
                          "size_in_bytes": 160,
                          "expired": false,
                          "archive_download_url": "https://api.github.com/repos/willibrandon/picket/actions/artifacts/701/zip"
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            includeActionArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        int redirectedRequestIndex = urls.IndexOf("https://productionresultssa1.blob.core.windows.net/actions-results/artifact.zip");
        Assert.HasCount(1, files);
        Assert.AreEqual("github/willibrandon/picket/actions/artifacts/build-701.zip!nested/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-444", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreNotEqual(-1, redirectedRequestIndex);
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts?per_page=100", requests);
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts/701/zip", requests);
        Assert.Contains("Bearer github-test-token", authorizationHeaders);
        Assert.Contains("application/vnd.github+json", acceptHeaders);
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[redirectedRequestIndex]);
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
    /// Verifies that default GitHub file byte limits skip oversized remote blobs.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesAppliesDefaultFileByteLimit()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"large.txt","type":"blob","size":100000001}]}""");
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
        Assert.Contains("GitHub file byte limit skipped github/willibrandon/picket/large.txt", warnings[0]);
        Assert.DoesNotContain("/contents/large.txt", string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that GitHub downloads stop when the body exceeds the byte cap even if the declared length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesAppliesByteLimitToUnderstatedContentLength()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"large.txt","type":"blob","size":4}]}""");
            }

            if (url.Contains("/contents/large.txt", StringComparison.Ordinal))
            {
                HttpResponseMessage response = BytesResponse("0123456789");
                response.Content.Headers.ContentLength = 1;
                return response;
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
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that GitHub source enumeration retries bounded rate-limit responses.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRetriesRateLimitedGitHubRequests()
    {
        const string Token = "github-test-token";
        int treeRequests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                treeRequests++;
                if (treeRequests == 1)
                {
                    return RetryAfterResponse((HttpStatusCode)429);
                }

                return JsonResponse("""{"tree":[]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            "main");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, treeRequests);
    }

    /// <summary>
    /// Verifies that GitHub source enumeration recognizes provider-specific forbidden rate-limit responses.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRetriesForbiddenGitHubRateLimitResponses()
    {
        const string Token = "github-test-token";
        int treeRequests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                treeRequests++;
                if (treeRequests == 1)
                {
                    HttpResponseMessage response = RetryAfterResponse(HttpStatusCode.Forbidden);
                    response.Headers.TryAddWithoutValidation("X-RateLimit-Remaining", "0");
                    return response;
                }

                return JsonResponse("""{"tree":[]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            "main");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, treeRequests);
    }

    /// <summary>
    /// Verifies that a caller-supplied HTTP client cannot silently auto-follow GitHub raw-content redirects.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesBlocksAutoFollowedRawContentRedirects()
    {
        const string Token = "github-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"secret.txt","type":"blob","size":12}]}""");
            }

            if (url.Contains("/contents/secret.txt?", StringComparison.Ordinal))
            {
                return AutoRedirectedBytesResponse("secret-token", "https://objects.example.invalid/secret.txt");
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
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
        Assert.Contains("421", warnings[0]);
    }

    /// <summary>
    /// Verifies provider-supplied repository paths are normalized before they become report paths.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesNormalizesUnsafeDisplayPathSegments()
    {
        const string Token = "github-test-token";
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"../secret.txt","type":"blob","size":11}]}""");
            }

            if (url.Contains("/contents/", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            if (url.Contains("/repos/willibrandon/picket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":"main"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubSourceOptions(GitHubSourceOptions.CreateDefaultEndpoint(), "willibrandon/picket", Token);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("github/willibrandon/picket/_/secret.txt", files[0].DisplayPath);
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
    /// Verifies that user repository enumeration follows paged repositories and scans each default branch.
    /// </summary>
    [TestMethod]
    public async Task EnumerateUserRepositoryFilesFollowsRepositoryPages()
    {
        const string Token = "github-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/users/octocat/repos?", StringComparison.Ordinal)
                && url.Contains("&page=1", StringComparison.Ordinal))
            {
                HttpResponseMessage response = JsonResponse("""[{"name":"one","full_name":"octocat/one","default_branch":"main"}]""");
                response.Headers.Add("Link", "<https://api.github.com/users/octocat/repos?type=member&per_page=100&page=2>; rel=\"next\"");
                return response;
            }

            if (url.Contains("/users/octocat/repos?", StringComparison.Ordinal)
                && url.Contains("&page=2", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"name":"two","full_name":"example/two","default_branch":"trunk"}]""");
            }

            if (url.Contains("/repos/octocat/one/git/trees/main?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"one.txt","type":"blob","size":9}]}""");
            }

            if (url.Contains("/repos/example/two/git/trees/trunk?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"two.txt","type":"blob","size":9}]}""");
            }

            if (url.Contains("/repos/octocat/one/contents/one.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-111");
            }

            if (url.Contains("/repos/example/two/contents/two.txt?", StringComparison.Ordinal))
            {
                return BytesResponse("token-222");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubUserSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "octocat",
            Token,
            repositoryType: "member");

        List<SourceFile> files = await client.EnumerateUserRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, files);
        Assert.AreEqual("github/octocat/one/one.txt", files[0].DisplayPath);
        Assert.AreEqual("github/example/two/two.txt", files[1].DisplayPath);
        Assert.Contains("type=member", string.Join('\n', urls));
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

    /// <summary>
    /// Verifies organization repository pagination stops at the safety limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateOrganizationRepositoryFilesStopsAtPaginationLimit()
    {
        const string Token = "github-test-token";
        int requestCount = 0;
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ =>
        {
            requestCount++;
            HttpResponseMessage response = JsonResponse("[]");
            response.Headers.TryAddWithoutValidation("Link", "<https://api.github.com/orgs/willibrandon/repos?page=2>; rel=\"next\"");
            return response;
        }));
        var client = new GitHubSourceClient(httpClient);
        var options = new GitHubOrganizationSourceOptions(
            GitHubSourceOptions.CreateDefaultEndpoint(),
            "willibrandon",
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateOrganizationRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1000, requestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("pagination safety limit", warnings[0]);
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

    private static HttpResponseMessage BytesResponse(byte[] value)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(value),
        };
    }

    private static HttpResponseMessage OversizedJsonMetadataResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([]),
        };
        response.Content.Headers.ContentLength = 10_000_001;
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return response;
    }

    private static HttpResponseMessage OversizedStreamingJsonMetadataResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatingReadStream(10_000_001, (byte)' ')),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return response;
    }

    private static HttpResponseMessage AutoRedirectedBytesResponse(string value, string redirectedUri)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(value)),
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, redirectedUri),
        };
    }

    private static HttpResponseMessage RetryAfterResponse(HttpStatusCode statusCode)
    {
        var response = new HttpResponseMessage(statusCode);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
        return response;
    }

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }
}
