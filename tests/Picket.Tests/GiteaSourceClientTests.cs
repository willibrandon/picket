using Picket.Sources;
using System.IO.Compression;
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
    /// Verifies that Gitea repository source options reject ambiguous pull request and Actions artifact scopes.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsPullRequestAndActionsArtifacts()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            pullRequestId: 7,
            includeActionArtifacts: true));

        Assert.Contains("cannot combine pull request and Actions artifact enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that Gitea Actions run filters require Actions artifact enumeration.
    /// </summary>
    [TestMethod]
    public void GiteaSourceOptionsRejectsActionsRunIdWithoutActionsArtifacts()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            actionRunId: 42));

        Assert.Contains("Actions run ID requires Actions artifact enumeration", ex.Message);
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
    /// Verifies that Gitea file display paths normalize unsafe provider path segments.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesNormalizesUnsafeDisplayPathSegments()
    {
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/repos/willibrandon/picket/branches/main", StringComparison.Ordinal))
            {
                return JsonResponse("""{"name":"main","commit":{"id":"abcdef1234567890"}}""");
            }

            if (url.Contains("/repos/willibrandon/picket/git/trees/abcdef1234567890?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"tree":[{"path":"safe/../secret.txt","type":"blob","size":11}],"truncated":false,"page":1,"total_count":1}""");
            }

            if (url.Contains("secret.txt", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaSourceOptions(
            GiteaSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitea-test-token",
            "main");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitea/willibrandon/picket/safe/_/secret.txt", files[0].DisplayPath);
    }

    /// <summary>
    /// Verifies that exact Gitea generic package files are downloaded and archive entries are expanded.
    /// </summary>
    [TestMethod]
    public async Task EnumerateGenericPackageFileExpandsArchiveContent()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        var acceptHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            urls.Add(request.RequestUri!.ToString());
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            acceptHeaders.Add(string.Join('\n', request.Headers.Accept.Select(static value => value.MediaType ?? string.Empty)));
            if (request.RequestUri!.ToString().Equals("https://gitea.example/api/packages/willibrandon/generic/picket-cli/1.0.0/picket.zip", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("pkg/secret.txt", "package-token-12345"));
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaGenericPackageSourceOptions(
            new Uri("https://gitea.example/api/v1/", UriKind.Absolute),
            "willibrandon",
            "picket-cli",
            "1.0.0",
            "picket.zip",
            Token);

        List<SourceFile> files = await client.EnumerateGenericPackageFileAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitea-package/willibrandon/picket-cli/1.0.0/picket.zip!pkg/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("package-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("https://gitea.example/api/packages/willibrandon/generic/picket-cli/1.0.0/picket.zip", urls);
        Assert.Contains("token gitea-test-token", authorizationHeaders);
        Assert.Contains("application/octet-stream", acceptHeaders);
    }

    /// <summary>
    /// Verifies that Gitea generic package owner enumeration lists package versions, lists files, and downloads selected files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateGenericPackageFilesReadsListedPackageFiles()
    {
        const string Token = "gitea-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            if (url.Equals("https://gitea.example/api/v1/packages/willibrandon?type=generic&page=1&limit=100", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"type":"generic","name":"picket-cli","version":"1.0.0"},{"type":"nuget","name":"Picket","version":"1.0.0"}]""");
            }

            if (url.Equals("https://gitea.example/api/v1/packages/willibrandon/generic/picket-cli/1.0.0/files", StringComparison.Ordinal))
            {
                return JsonResponse("""[{"name":"secrets.txt","size":19},{"name":"too-large.txt","size":100000001}]""");
            }

            if (url.Equals("https://gitea.example/api/packages/willibrandon/generic/picket-cli/1.0.0/secrets.txt", StringComparison.Ordinal))
            {
                return BytesResponse("package-token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GiteaSourceClient(httpClient);
        var options = new GiteaGenericPackageOwnerSourceOptions(
            new Uri("https://gitea.example/api/v1/", UriKind.Absolute),
            "willibrandon",
            Token);

        List<SourceFile> files = await client.EnumerateGenericPackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitea-package/willibrandon/picket-cli/1.0.0/secrets.txt", files[0].DisplayPath);
        Assert.AreEqual("package-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/api/v1/packages/willibrandon?type=generic&page=1&limit=100", requests);
        Assert.Contains("/api/v1/packages/willibrandon/generic/picket-cli/1.0.0/files", requests);
        Assert.Contains("/api/packages/willibrandon/generic/picket-cli/1.0.0/secrets.txt", requests);
        Assert.Contains("token gitea-test-token", authorizationHeaders);
        Assert.DoesNotContain("/api/packages/willibrandon/generic/picket-cli/1.0.0/too-large.txt", requests);
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
    /// Verifies that Actions artifact enumeration downloads artifact ZIP redirects without forwarding credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsActionsArtifactsWithoutRedirectAuthorization()
    {
        const string Token = "gitea-test-token";
        byte[] archiveBytes = CreateZipBytes("nested/secret.txt", "artifact-token-12345");
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

            if (url.Contains("/repos/willibrandon/picket/actions/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    $$"""
                    {
                      "total_count": 3,
                      "artifacts": [
                        {"id": 701, "name": "build", "size_in_bytes": {{archiveBytes.Length}}, "expired": false},
                        {"id": 702, "name": "expired", "size_in_bytes": 1, "expired": true},
                        {"id": 703, "name": "too-large", "size_in_bytes": 100000001, "expired": false}
                      ]
                    }
                    """);
            }

            if (url.Equals("https://gitea.example/api/v1/repos/willibrandon/picket/actions/artifacts/701/zip", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Found)
                {
                    Headers =
                    {
                        Location = new Uri("https://artifacts.example/build.zip", UriKind.Absolute),
                    },
                };
            }

            if (url.Equals("https://artifacts.example/build.zip", StringComparison.Ordinal))
            {
                return BytesResponse(archiveBytes);
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
            includeActionArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        int redirectRequestIndex = urls.IndexOf("https://artifacts.example/build.zip");
        Assert.HasCount(1, files);
        Assert.AreEqual("gitea/willibrandon/picket/actions/artifacts/build-701.zip!nested/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts?page=1&limit=100", requests);
        Assert.Contains("/repos/willibrandon/picket/actions/artifacts/701/zip", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/actions/artifacts/702/zip", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/actions/artifacts/703/zip", requests);
        Assert.AreNotEqual(-1, redirectRequestIndex);
        Assert.Contains("token gitea-test-token", authorizationHeaders);
        Assert.AreEqual(string.Empty, authorizationHeaders[redirectRequestIndex]);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that Actions artifact enumeration can be scoped to a single Gitea Actions run.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsActionsArtifactsForRun()
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

            if (url.Contains("/repos/willibrandon/picket/actions/runs/42/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"total_count":0,"artifacts":[]}""");
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
            includeActionArtifacts: true,
            actionRunId: 42);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.IsEmpty(files);
        Assert.Contains("/repos/willibrandon/picket/actions/runs/42/artifacts?page=1&limit=100", requests);
        Assert.DoesNotContain("/repos/willibrandon/picket/actions/artifacts?", requests);
    }

    /// <summary>
    /// Verifies that Actions artifact archive URLs cannot send credentials outside the configured Gitea API origin.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsUnexpectedActionsArtifactArchiveUrls()
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

            if (url.Contains("/repos/willibrandon/picket/actions/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "artifacts": [
                        {
                          "id": 701,
                          "name": "build",
                          "size_in_bytes": 10,
                          "archive_download_url": "https://gitea.example/downloads/build.zip"
                        }
                      ]
                    }
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
            includeActionArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.IsEmpty(files);
        Assert.DoesNotContain("https://gitea.example/downloads/build.zip", requests);
        Assert.Contains("archive URL is not an allowed Gitea API endpoint", string.Join('\n', warnings));
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

    private static HttpResponseMessage BytesResponse(byte[] bytes)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes),
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
