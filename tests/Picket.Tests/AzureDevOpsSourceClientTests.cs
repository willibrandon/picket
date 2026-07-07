using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Azure DevOps source enumeration.
/// </summary>
[TestClass]
public sealed class AzureDevOpsSourceClientTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that repository enumeration follows Azure DevOps continuation tokens and downloads blob content.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsPagedRepositoriesAndBlobContent()
    {
        const string Token = "azdo-test-token";
        var urls = new List<string>();
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            CaptureRequest(request, urls, authorizationHeaders);
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal)
                && url.Contains("continuationToken=next", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                HttpResponseMessage response = JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": "repo-1",
                          "name": "web",
                          "project": { "name": "Project One" }
                        }
                      ]
                    }
                    """);
                response.Headers.TryAddWithoutValidation("x-ms-continuationtoken", "next");
                return response;
            }

            if (url.Contains("/items?", StringComparison.Ordinal)
                && url.Contains("download=true", StringComparison.Ordinal))
            {
                return BytesResponse("connection=secret");
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        { "path": "/src/appsettings.json", "gitObjectType": "blob" },
                        { "path": "/src", "gitObjectType": "tree" }
                      ]
                    }
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"), Token);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops/Project%20One/web/src/appsettings.json", files[0].DisplayPath);
        Assert.AreEqual("connection=secret", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("continuationToken=next", string.Join('\n', urls));
        Assert.Contains(
            string.Concat("Basic ", Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(":", Token)))),
            authorizationHeaders);
        Assert.DoesNotContain(Token, string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that pull request enumeration resolves the source commit before listing repository items.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsPullRequestSourceCommit()
    {
        const string Token = "azdo-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": "repo-1",
                          "name": "web",
                          "defaultBranch": null,
                          "project": { "name": "Project One" }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/_apis/git/repositories/repo-1/pullRequests/42?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "pullRequestId": 42,
                      "sourceRefName": "refs/heads/feature/secret",
                      "lastMergeSourceCommit": {
                        "commitId": "abcdef1234567890"
                      },
                      "forkSource": {
                        "repository": {
                          "id": "fork-repo",
                          "name": "fork-web",
                          "project": { "name": "Fork Project" }
                        }
                      }
                    }
                    """);
            }

            if (url.Contains("/items?", StringComparison.Ordinal)
                && url.Contains("download=true", StringComparison.Ordinal))
            {
                return BytesResponse("pr-token-12345");
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"path":"/src/pr.txt","gitObjectType":"blob"}]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            repository: "web",
            pullRequestId: 42);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops/Fork%20Project/fork-web/src/pr.txt", files[0].DisplayPath);
        Assert.AreEqual("pr-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("/pullRequests/42?", requests);
        Assert.Contains("/repositories/fork-repo/items?", requests);
        Assert.DoesNotContain("/repositories/repo-1/items?", requests);
        Assert.Contains("versionDescriptor.version=abcdef1234567890", requests);
        Assert.Contains("versionDescriptor.versionType=commit", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that wiki backing repositories are scanned only when explicitly enabled.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesIncludesWikiRepositoriesWhenEnabled()
    {
        const string Token = "azdo-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("/_apis/wiki/wikis?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "name": "Team Wiki",
                          "repositoryId": "wiki-repo",
                          "projectId": "Project One",
                          "mappedPath": "/docs",
                          "versions": [
                            { "version": "wikiMaster" }
                          ]
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/Project One/_apis/git/repositories/wiki-repo/items?", StringComparison.Ordinal)
                && url.Contains("download=true", StringComparison.Ordinal))
            {
                return BytesResponse("wiki-token-12345");
            }

            if (url.Contains("/Project One/_apis/git/repositories/wiki-repo/items?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        { "path": "/docs/Home.md", "gitObjectType": "blob" },
                        { "path": "/docs", "gitObjectType": "tree" }
                      ]
                    }
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            includeWikis: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops-wiki/Project%20One/Team%20Wiki/docs/Home.md", files[0].DisplayPath);
        Assert.AreEqual("wiki-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("scopePath=%2Fdocs", string.Join('\n', urls));
        Assert.Contains("versionDescriptor.version=wikiMaster", string.Join('\n', urls));
        Assert.DoesNotContain(Token, string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that build artifacts and build logs are scanned only when explicitly enabled.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsBuildArtifactsAndLogsWhenEnabled()
    {
        const string Token = "azdo-test-token";
        var urls = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("nested/artifact.txt", "artifact-token-12345"));
            }

            if (url.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": 12,
                          "name": "drop",
                          "resource": {
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/artifacts?artifactName=drop&api-version=7.1"
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/_apis/build/builds/77/logs?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"id":4,"type":"container","url":"https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/logs/4"}]}""");
            }

            if (url.Contains("/_apis/build/builds/77/logs/4?", StringComparison.Ordinal))
            {
                return BytesResponse("log-token-67890");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            buildId: 77,
            includeArtifacts: true,
            includeLogs: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, files);
        Assert.AreEqual("azure-devops-build/Project%20One/77/artifacts/drop.zip!nested/artifact.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual("azure-devops-build/Project%20One/77/logs/4.log", files[1].DisplayPath);
        Assert.AreEqual("log-token-67890", Encoding.UTF8.GetString(files[1].ReadAllBytes()));
        Assert.Contains("/_apis/build/builds/77/artifacts?", string.Join('\n', urls));
        Assert.Contains("/_apis/build/builds/77/logs?", string.Join('\n', urls));
        Assert.DoesNotContain(Token, string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that redirected artifact downloads do not forward Azure DevOps credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesDownloadsRedirectedBuildArtifactsWithoutCredentials()
    {
        const string Token = "azdo-test-token";
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal)
                && !url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "name": "drop",
                          "resource": {
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/artifacts?artifactName=drop&api-version=7.1"
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers =
                    {
                        Location = new Uri("https://picket.blob.core.windows.net/artifacts/drop.zip"),
                    },
                };
            }

            if (url.Equals("https://picket.blob.core.windows.net/artifacts/drop.zip", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("artifact.txt", "artifact-token-54321"));
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            buildId: 77,
            includeArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops-build/Project%20One/77/artifacts/drop.zip!artifact.txt", files[0].DisplayPath);
        Assert.AreEqual("artifact-token-54321", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.AreEqual(string.Empty, authorizationHeaders[^1]);
        Assert.Contains("Basic ", authorizationHeaders[0]);
    }

    /// <summary>
    /// Verifies that build artifacts and logs require an explicit project and build ID.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsRejectsBuildSourcesWithoutBuildScope()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            buildId: 77,
            includeArtifacts: true));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            project: "Project One",
            includeLogs: true));
    }

    /// <summary>
    /// Verifies that Azure Pipelines job tokens use Bearer authorization instead of PAT Basic authorization.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesUsesBearerCredentialForJobTokens()
    {
        const string Token = "job-token";
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            return JsonResponse("""{"value":[]}""");
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            AzureDevOpsCredentialKind.BearerToken);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains("Bearer job-token", authorizationHeaders);
    }

    /// <summary>
    /// Verifies that empty repositories with no default branch do not fail whole-source enumeration.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsRepositoriesWithoutDefaultBranch()
    {
        const string Token = "azdo-test-token";
        var urls = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            urls.Add(url);
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": "repo-1",
                          "name": "empty",
                          "defaultBranch": null,
                          "project": { "name": "Project One" }
                        }
                      ]
                    }
                    """);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("does not have a default branch", warnings[0]);
        Assert.DoesNotContain("/items?", string.Join('\n', urls));
    }

    /// <summary>
    /// Verifies that a repository item-list failure is reported without failing other repositories.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesSkipsRepositoriesWhoseItemsCannotBeListed()
    {
        const string Token = "azdo-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": "repo-1",
                          "name": "empty",
                          "project": { "name": "Project One" }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("skipping Azure DevOps repository empty", warnings[0]);
        Assert.Contains("404 NotFound", warnings[0]);
    }

    /// <summary>
    /// Verifies that Azure DevOps file byte caps skip oversized blobs without logging credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesHonorsFileByteCap()
    {
        const string Token = "azdo-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "id": "repo-1",
                          "name": "web",
                          "project": { "name": "Project One" }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/items?", StringComparison.Ordinal)
                && url.Contains("download=true", StringComparison.Ordinal))
            {
                return BytesResponse("0123456789");
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"path":"/large.txt","gitObjectType":"blob"}]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            repository: "web",
            maxFileBytes: 4,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps file byte limit skipped azure-devops/Project%20One/web/large.txt", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    private static void CaptureRequest(
        HttpRequestMessage request,
        List<string> urls,
        List<string> authorizationHeaders)
    {
        urls.Add(request.RequestUri!.ToString());
        authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
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
