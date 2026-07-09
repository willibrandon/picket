using Picket.Sources;
using System.IO.Compression;
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
    /// Verifies that GitLab source options reject ambiguous ref and merge request scopes.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsRefAndMergeRequest()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            "main",
            mergeRequestIid: 42));

        Assert.Contains("either a ref or a merge request ID", ex.Message);
    }

    /// <summary>
    /// Verifies that GitLab source options reject ambiguous merge request and snippet scopes.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsMergeRequestAndSnippets()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            mergeRequestIid: 42,
            includeSnippets: true));

        Assert.Contains("cannot combine merge request scans with snippet enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that GitLab source options reject ambiguous merge request and job artifact scopes.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsMergeRequestAndJobArtifacts()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            mergeRequestIid: 42,
            includeJobArtifacts: true));

        Assert.Contains("cannot combine merge request scans with job artifact enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that GitLab source options reject ambiguous merge request and job log scopes.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsMergeRequestAndJobLogs()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            mergeRequestIid: 42,
            includeJobLogs: true));

        Assert.Contains("cannot combine merge request scans with job log enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that GitLab source options reject ambiguous merge request and package file scopes.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsMergeRequestAndPackages()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            mergeRequestIid: 42,
            includePackages: true));

        Assert.Contains("cannot combine merge request scans with package file enumeration", ex.Message);
    }

    /// <summary>
    /// Verifies that GitLab source options reject pipeline-scoped job enumeration without a job source.
    /// </summary>
    [TestMethod]
    public void GitLabSourceOptionsRejectsPipelineWithoutJobEnumeration()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            pipelineId: 123));

        Assert.Contains("pipeline source scans require job log or job artifact enumeration", ex.Message);
    }

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
    /// Verifies that GitLab group URLs normalize to group paths.
    /// </summary>
    [TestMethod]
    public void GitLabGroupSourceOptionsNormalizesGroupUrls()
    {
        var options = new GitLabGroupSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "https://gitlab.com/groups/team/platform",
            "gitlab-test-token");

        Assert.AreEqual("team/platform", options.Group);
    }

    /// <summary>
    /// Verifies that GitLab repository tree enumeration retries one bounded rate-limit response.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRetriesRateLimitedTreeRequests()
    {
        var warnings = new List<string>();
        int treeAttempts = 0;
        var handler = new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
            {
                treeAttempts++;
                return treeAttempts == 1
                    ? RetryAfterResponse()
                    : JsonResponse("[]");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        using var httpClient = new HttpClient(handler);
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            "main",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.IsEmpty(warnings);
        Assert.AreEqual(2, treeAttempts);
        Assert.AreEqual(2, handler.RequestCount);
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
    /// Verifies that GitLab repository enumeration normalizes unsafe provider-supplied display path segments.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesNormalizesUnsafeDisplayPathSegments()
    {
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "path": "safe/../secret.txt", "type": "blob", "size": 11 }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/repository/files/safe%2F..%2Fsecret.txt/raw?", StringComparison.Ordinal))
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
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab/willibrandon/picket/safe/_/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
    }

    /// <summary>
    /// Verifies that group enumeration lists group projects and scans each project repository.
    /// </summary>
    [TestMethod]
    public async Task EnumerateGroupRepositoryFilesReadsProjectRepositories()
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
            if (url.Contains("/groups/team%2Fplatform/projects?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "id": 321, "path_with_namespace": "team/platform/api", "default_branch": "main" }]""");
            }

            if (url.Contains("/projects/team%2Fplatform%2Fapi/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "path": "src/appsettings.txt", "type": "blob", "size": 11 }]""");
            }

            if (url.Contains("/projects/team%2Fplatform%2Fapi/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabGroupSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "team/platform",
            Token,
            includeSubgroups: true);

        List<SourceFile> files = await client.EnumerateGroupRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab/team/platform/api/src/appsettings.txt", files[0].DisplayPath);
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/groups/team%2Fplatform/projects?", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("page=1", requests);
        Assert.Contains("include_subgroups=true", requests);
        Assert.Contains("/projects/team%2Fplatform%2Fapi/repository/tree?", requests);
        Assert.Contains("ref=main", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that group enumeration skips a project whose metadata request fails and continues with later projects.
    /// </summary>
    [TestMethod]
    public async Task EnumerateGroupRepositoryFilesContinuesWhenProjectMetadataRequestFails()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/groups/team%2Fplatform/projects?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      { "id": 100, "path_with_namespace": "team/platform/missing" },
                      { "id": 321, "path_with_namespace": "team/platform/api", "default_branch": "main" }
                    ]
                    """);
            }

            if (url.Contains("/projects/team%2Fplatform%2Fmissing", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (url.Contains("/projects/team%2Fplatform%2Fapi/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "path": "src/appsettings.txt", "type": "blob", "size": 11 }]""");
            }

            if (url.Contains("/projects/team%2Fplatform%2Fapi/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
            {
                return BytesResponse("token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabGroupSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "team/platform",
            "gitlab-test-token",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateGroupRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab/team/platform/api/src/appsettings.txt", files[0].DisplayPath);
        Assert.Contains("skipping GitLab project team/platform/missing because GitLab returned 404 NotFound", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that merge request enumeration resolves the source project and head SHA before reading files.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsMergeRequestSourceHeadFiles()
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
            if (url.Contains("/projects/willibrandon%2Fpicket/merge_requests/42", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "iid": 42,
                      "source_project_id": 123,
                      "target_project_id": 456,
                      "source_branch": "feature/scan",
                      "sha": "sha-from-merge-request",
                      "diff_refs": {
                        "head_sha": "abcdef1234567890"
                      }
                    }
                    """);
            }

            if (url.Contains("/projects/123/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "path": "src/pr.txt", "type": "blob", "size": 14 }]""");
            }

            if (url.Contains("/projects/123/repository/files/src%2Fpr.txt/raw?", StringComparison.Ordinal))
            {
                return BytesResponse("pr-token-12345");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            mergeRequestIid: 42);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab/123/src/pr.txt", files[0].DisplayPath);
        Assert.AreEqual("pr-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/projects/willibrandon%2Fpicket/merge_requests/42", requests);
        Assert.Contains("/projects/123/repository/tree?", requests);
        Assert.Contains("ref=abcdef1234567890", requests);
        Assert.DoesNotContain("/projects/willibrandon%2Fpicket/repository/tree?", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that merge request enumeration falls back to the source branch when SHA fields are absent.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesUsesMergeRequestSourceBranchFallback()
    {
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/projects/willibrandon%2Fpicket/merge_requests/42", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "iid": 42,
                      "source_project_id": 123,
                      "target_project_id": 123,
                      "source_branch": "feature/scan",
                      "diff_refs": {}
                    }
                    """);
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("[]");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            mergeRequestIid: 42);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.IsEmpty(files);
        Assert.Contains("/projects/willibrandon%2Fpicket/repository/tree?", requests);
        Assert.Contains("ref=feature%2Fscan", requests);
    }

    /// <summary>
    /// Verifies that project snippet enumeration lists snippets and downloads raw snippet content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesProjectSnippets()
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
                return JsonResponse("[]");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/snippets?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "id": 7, "file_name": "ops/token.txt", "raw_url": "https://gitlab.example/snippets/7/raw" }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/snippets/7/raw", StringComparison.Ordinal))
            {
                return BytesResponse("snippet-token-12345");
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
            Token,
            includeSnippets: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab-snippet/willibrandon/picket/7/ops/token.txt", files[0].DisplayPath);
        Assert.AreEqual("snippet-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/projects/willibrandon%2Fpicket/snippets?", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("page=1", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/snippets/7/raw", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", acceptHeaders);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that snippet enumeration does not depend on the project default branch.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesProjectSnippetsWithoutDefaultBranch()
    {
        var urls = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/projects/willibrandon%2Fpicket/snippets?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "id": 7, "file_name": "ops/token.txt" }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/snippets/7/raw", StringComparison.Ordinal))
            {
                return BytesResponse("snippet-token-12345");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket", StringComparison.Ordinal))
            {
                return JsonResponse("""{"default_branch":""}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            "gitlab-test-token",
            includeSnippets: true,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab-snippet/willibrandon/picket/7/ops/token.txt", files[0].DisplayPath);
        Assert.Contains("skipping GitLab project willibrandon/picket because it does not have a default branch", string.Join('\n', warnings));
        Assert.DoesNotContain("/repository/tree?", requests);
    }

    /// <summary>
    /// Verifies that job enumeration can include logs and expanded artifact archives.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesJobLogsAndArtifacts()
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
                return JsonResponse("[]");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 99,
                        "name": "build",
                        "artifacts_file": {
                          "filename": "artifacts.zip",
                          "size": 128
                        }
                      }
                    ]
                    """);
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs/99/trace", StringComparison.Ordinal))
            {
                return BytesResponse("log-token-12345");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs/99/artifacts", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("out/secret.txt", "artifact-token-12345"));
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
            Token,
            includeJobArtifacts: true,
            includeJobLogs: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("gitlab-job-log/willibrandon/picket/99-build.log", files[0].DisplayPath);
        Assert.AreEqual("log-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("gitlab-job-artifact/willibrandon/picket/99/artifacts.zip!out/secret.txt", files[1].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/projects/willibrandon%2Fpicket/jobs?", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("page=1", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/jobs/99/trace", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/jobs/99/artifacts", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", string.Join('\n', acceptHeaders));
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that pipeline-scoped job enumeration lists jobs through the selected pipeline endpoint.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesPipelineJobLogsAndArtifacts()
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
                return JsonResponse("[]");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/pipelines/123/jobs?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      {
                        "id": 99,
                        "name": "build",
                        "artifacts_file": {
                          "filename": "artifacts.zip",
                          "size": 128
                        }
                      }
                    ]
                    """);
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs/99/trace", StringComparison.Ordinal))
            {
                return BytesResponse("log-token-12345");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs/99/artifacts", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("out/secret.txt", "artifact-token-12345"));
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new GitLabSourceClient(httpClient);
        var options = new GitLabSourceOptions(
            GitLabSourceOptions.CreateDefaultEndpoint(),
            "willibrandon/picket",
            Token,
            gitRef: "main",
            includeJobArtifacts: true,
            includeJobLogs: true,
            pipelineId: 123);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(2, files);
        Assert.AreEqual("gitlab-job-log/willibrandon/picket/99-build.log", files[0].DisplayPath);
        Assert.AreEqual("log-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("gitlab-job-artifact/willibrandon/picket/99/artifacts.zip!out/secret.txt", files[1].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/projects/willibrandon%2Fpicket/pipelines/123/jobs?", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("page=1", requests);
        Assert.DoesNotContain("/projects/willibrandon%2Fpicket/jobs?per_page", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/jobs/99/trace", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/jobs/99/artifacts", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", string.Join('\n', acceptHeaders));
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that package enumeration lists generic package files and expands archive content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesGenericPackages()
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
                return JsonResponse("[]");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/packages/4/package_files?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "id": 25, "file_name": "picket.zip", "size": 128, "file_sha256": "abc" }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/packages/generic/picket-cli/1.0.0/picket.zip", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("pkg/secret.txt", "package-token-12345"));
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/packages?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    [
                      { "id": 4, "name": "picket-cli", "version": "1.0.0", "package_type": "generic" },
                      { "id": 5, "name": "ignored", "version": "1.0.0", "package_type": "maven" }
                    ]
                    """);
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
            Token,
            includePackages: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab-package/willibrandon/picket/picket-cli/1.0.0/picket.zip!pkg/secret.txt", files[0].DisplayPath);
        Assert.AreEqual("package-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/projects/willibrandon%2Fpicket/packages?", requests);
        Assert.Contains("package_type=generic", requests);
        Assert.Contains("per_page=100", requests);
        Assert.Contains("page=1", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/packages/4/package_files?", requests);
        Assert.Contains("/projects/willibrandon%2Fpicket/packages/generic/picket-cli/1.0.0/picket.zip", requests);
        Assert.Contains("PRIVATE-TOKEN", string.Join('\n', privateTokens));
        Assert.Contains("gitlab-test-token", string.Join('\n', privateTokens));
        Assert.DoesNotContain("Bearer", string.Join('\n', authorizationHeaders));
        Assert.Contains("application/octet-stream", string.Join('\n', acceptHeaders));
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that redirected GitLab artifact downloads do not forward the source token.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesDownloadsRedirectedJobArtifactsWithoutToken()
    {
        const string Token = "gitlab-test-token";
        var urls = new List<string>();
        var privateTokens = new List<string>();
        var redirectedPrivateTokens = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            string privateToken = request.Headers.TryGetValues("PRIVATE-TOKEN", out IEnumerable<string>? privateTokenValues)
                ? string.Join(" ", privateTokenValues)
                : string.Empty;
            privateTokens.Add(privateToken);
            if (url.Contains("cdn.gitlab.example", StringComparison.Ordinal))
            {
                redirectedPrivateTokens.Add(privateToken);
                return BytesResponse(CreateZipBytes("artifact.txt", "artifact-token-12345"));
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
            {
                return JsonResponse("[]");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs?", StringComparison.Ordinal))
            {
                return JsonResponse("""[{ "id": 99, "name": "build", "artifacts_file": { "filename": "artifacts.zip", "size": 128 } }]""");
            }

            if (url.Contains("/projects/willibrandon%2Fpicket/jobs/99/artifacts", StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.gitlab.example/artifacts.zip?signature=abc");
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
            Token,
            includeJobArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("gitlab-job-artifact/willibrandon/picket/99/artifacts.zip!artifact.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains(Token, string.Join('\n', privateTokens));
        Assert.Contains("https://cdn.gitlab.example/artifacts.zip?signature=abc", string.Join('\n', urls));
        Assert.HasCount(1, redirectedPrivateTokens);
        Assert.IsEmpty(redirectedPrivateTokens[0]);
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

    private static HttpResponseMessage BytesResponse(byte[] bytes)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(bytes),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return response;
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

    private static HttpResponseMessage RetryAfterResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
        return response;
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
