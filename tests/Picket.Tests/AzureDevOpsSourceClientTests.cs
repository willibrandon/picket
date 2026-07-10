using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
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
    /// Verifies that Azure DevOps source options default to bounded remote downloads.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsDefaultsToBoundedRemoteDownloads()
    {
        var options = new AzureDevOpsSourceOptions(AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"), "azdo-test-token");

        Assert.AreEqual(100_000_000, options.MaxFileBytes);
        Assert.AreEqual(100_000_000, options.MaxArtifactBytes);
        Assert.AreEqual(100_000_000, options.MaxLogBytes);
        Assert.AreEqual(100_000_000, options.MaxPackageBytes);
    }

    /// <summary>
    /// Verifies that Azure DevOps source options reject unbounded remote downloads.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsRejectsZeroForUnboundedRemoteDownloads()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "azdo-test-token",
            maxFileBytes: 0,
            maxArtifactBytes: 0,
            maxLogBytes: 0,
            maxPackageBytes: 0));
    }

    /// <summary>
    /// Verifies Azure DevOps source options reject credentials over public HTTP by default.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsRejectsPublicHttpCredentialTransportByDefault()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            new Uri("http://dev.azure.com/picket/"),
            "azdo-test-token"));
    }

    /// <summary>
    /// Verifies Azure DevOps source options require an explicit opt-in for public HTTP credential transport.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsAcceptsExplicitPublicHttpCredentialTransport()
    {
        var options = new AzureDevOpsSourceOptions(
            new Uri("http://dev.azure.com/picket/"),
            "azdo-test-token",
            allowInsecureCredentialTransport: true);

        Assert.AreEqual("http://dev.azure.com/picket/", options.Endpoint.AbsoluteUri);
    }

    /// <summary>
    /// Verifies that Azure DevOps JSON metadata stops before reading responses that declare a size beyond the metadata cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRejectsMetadataResponseExceedingCap()
    {
        const string Token = "azdo-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => OversizedJsonMetadataResponse()));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps source metadata", warnings[0]);
        Assert.Contains("exceeding the 10000000 byte metadata cap", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that Azure DevOps JSON metadata is capped while streaming when no content length is available.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRejectsStreamingMetadataResponseExceedingCap()
    {
        const string Token = "azdo-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => OversizedStreamingJsonMetadataResponse()));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps source metadata", warnings[0]);
        Assert.Contains("remote metadata response exceeded the 10000000 byte metadata cap", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

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
    /// Verifies that artifact request failures omit signed request details and do not suppress independent log scans.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesContinuesToLogsAfterSafeArtifactRequestFailure()
    {
        const string Token = "azdo-test-token";
        const string SignedQuerySecret = "signed-query-secret-12345";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                throw new HttpRequestException(string.Concat("download failed at ", url));
            }

            if (url.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    $$"""
                    {
                      "value": [
                        {
                          "id": 12,
                          "name": "drop",
                          "resource": {
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/artifacts?artifactName=drop&sig={{SignedQuerySecret}}"
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/_apis/build/builds/77/logs?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"id":4}]}""");
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
            includeLogs: true,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);
        string diagnostics = string.Join('\n', warnings);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops-build/Project%20One/77/logs/4.log", files[0].DisplayPath);
        Assert.AreEqual("log-token-67890", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("skipping Azure DevOps build artifacts because a request failed", diagnostics);
        Assert.DoesNotContain(SignedQuerySecret, diagnostics);
        Assert.DoesNotContain("download failed at", diagnostics);
    }

    /// <summary>
    /// Verifies that build-scoped sources remain available when the credential cannot enumerate repositories.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsBuildSourcesWhenRepositoryEnumerationIsForbidden()
    {
        const string Token = "azdo-test-token";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Forbidden);
            }

            if (url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("artifact.txt", "artifact-token-12345"));
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
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/artifacts?artifactName=drop"
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("/_apis/build/builds/77/logs?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"id":4}]}""");
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
            includeLogs: true,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, files);
        Assert.AreEqual("azure-devops-build/Project%20One/77/artifacts/drop.zip!artifact.txt", files[0].DisplayPath);
        Assert.AreEqual("azure-devops-build/Project%20One/77/logs/4.log", files[1].DisplayPath);
        Assert.Contains("skipping Azure DevOps repositories because a request failed", string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies that archive safety warnings omit provider-controlled artifact and entry paths.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRedactsArtifactPathsFromArchiveWarnings()
    {
        const string Token = "azdo-test-token";
        const string ArtifactNameSecret = "artifact-name-secret-12345";
        const string EntryNameSecret = "entry-name-secret-67890";
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[]}""");
            }

            if (url.Contains("artifactName=drop", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes(
                    "first.txt",
                    "first",
                    string.Concat(EntryNameSecret, ".txt"),
                    "second"));
            }

            if (url.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    $$"""
                    {
                      "value": [
                        {
                          "id": 12,
                          "name": "{{ArtifactNameSecret}}",
                          "resource": {
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/77/artifacts?artifactName=drop"
                          }
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
            project: "Project One",
            buildId: 77,
            includeArtifacts: true,
            maxArchiveEntries: 1,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);
        string diagnostics = string.Join('\n', warnings);

        Assert.HasCount(1, files);
        Assert.Contains("archive entry limit reached after 1 entries while reading Azure DevOps build 77 artifact", diagnostics);
        Assert.DoesNotContain(ArtifactNameSecret, diagnostics);
        Assert.DoesNotContain(EntryNameSecret, diagnostics);
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
    /// Verifies that classic Azure DevOps release artifacts are scanned only when explicitly enabled.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesReadsClassicReleaseArtifactsWhenEnabled()
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

            if (url.Contains("/_apis/release/releases/88?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "id": 88,
                      "artifacts": [
                        {
                          "alias": "drop",
                          "type": "Build",
                          "definitionReference": {
                            "version": { "id": "99" },
                            "project": { "name": "Project One" }
                          }
                        }
                      ]
                    }
                    """);
            }

            if (url.Contains("artifactName=release-drop", StringComparison.Ordinal))
            {
                return BytesResponse(CreateZipBytes("release/artifact.txt", "release-token-12345"));
            }

            if (url.Contains("/_apis/build/builds/99/artifacts?", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "value": [
                        {
                          "name": "release-drop",
                          "resource": {
                            "downloadUrl": "https://dev.azure.com/picket/Project%20One/_apis/build/builds/99/artifacts?artifactName=release-drop&api-version=7.1"
                          }
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
            project: "Project One",
            releaseId: 88,
            includeReleaseArtifacts: true);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        string requests = string.Join('\n', urls);
        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops-release/Project%20One/88/artifacts/drop/release-drop.zip!release/artifact.txt", files[0].DisplayPath);
        Assert.AreEqual("release-token-12345", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.Contains("https://vsrm.dev.azure.com/picket/Project One/_apis/release/releases/88?", requests);
        Assert.Contains("https://dev.azure.com/picket/Project One/_apis/build/builds/99/artifacts?", requests);
        Assert.DoesNotContain(Token, requests);
    }

    /// <summary>
    /// Verifies that build artifacts, logs, and release artifacts require explicit source scope.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsSourceOptionsRejectsRemoteArtifactsWithoutRequiredScope()
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
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            releaseId: 88,
            includeReleaseArtifacts: true));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            project: "Project One",
            includeReleaseArtifacts: true));
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
        Assert.Contains("Azure DevOps file azure-devops/Project%20One/web/large.txt skipped because the byte limit was exceeded", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that default Azure DevOps file byte limits skip oversized remote downloads.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesAppliesDefaultFileByteLimit()
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
                HttpResponseMessage response = BytesResponse("short");
                response.Content.Headers.ContentLength = 100_000_001;
                return response;
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
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps file azure-devops/Project%20One/web/large.txt skipped because the byte limit was exceeded", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that Azure DevOps downloads stop when the body exceeds the byte cap even if the declared length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesAppliesByteLimitToUnderstatedContentLength()
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
                HttpResponseMessage response = BytesResponse("0123456789");
                response.Content.Headers.ContentLength = 1;
                return response;
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
        Assert.Contains("Azure DevOps file azure-devops/Project%20One/web/large.txt skipped because the byte limit was exceeded", warnings[0]);
        Assert.DoesNotContain(Token, warnings[0]);
    }

    /// <summary>
    /// Verifies that Azure DevOps source enumeration retries bounded rate-limit responses.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesRetriesRateLimitedAzureDevOpsRequests()
    {
        const string Token = "azdo-test-token";
        int repositoryRequests = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string url = request.RequestUri!.ToString();
            if (url.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
            {
                repositoryRequests++;
                if (repositoryRequests == 1)
                {
                    return RetryAfterResponse((HttpStatusCode)429);
                }

                return JsonResponse("""{"value":[]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, repositoryRequests);
    }

    /// <summary>
    /// Verifies that a caller-supplied HTTP client cannot silently auto-follow Azure DevOps file redirects.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesBlocksAutoFollowedFileRedirects()
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
                return AutoRedirectedBytesResponse("secret-token", "https://objects.example.invalid/secret.txt");
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"path":"/secret.txt","gitObjectType":"blob"}]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            repository: "web",
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
        const string Token = "azdo-test-token";
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
                return BytesResponse("token-12345");
            }

            if (url.Contains("/items?", StringComparison.Ordinal))
            {
                return JsonResponse("""{"value":[{"path":"../secret.txt","gitObjectType":"blob"}]}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            project: "Project One",
            repository: "web");

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops/Project%20One/web/_/secret.txt", files[0].DisplayPath);
    }

    /// <summary>
    /// Verifies repository continuation-token pagination stops at the safety limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateRepositoryFilesStopsAtContinuationLimit()
    {
        const string Token = "azdo-test-token";
        int requestCount = 0;
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ =>
        {
            requestCount++;
            HttpResponseMessage response = JsonResponse("""{"value":[]}""");
            response.Headers.TryAddWithoutValidation("x-ms-continuationtoken", "next");
            return response;
        }));
        var client = new AzureDevOpsSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            Token,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateRepositoryFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1000, requestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("pagination safety limit", warnings[0]);
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

    private static HttpResponseMessage OversizedJsonMetadataResponse()
    {
        HttpResponseMessage response = JsonResponse("{}");
        response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
        return response;
    }

    private static HttpResponseMessage OversizedStreamingJsonMetadataResponse()
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatingReadStream(RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1, (byte)' ')),
        };
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

    private static byte[] CreateZipBytes(string entryName, string content)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntry(archive, entryName, content);
        }

        return stream.ToArray();
    }

    private static byte[] CreateZipBytes(
        string firstEntryName,
        string firstContent,
        string secondEntryName,
        string secondContent)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntry(archive, firstEntryName, firstContent);
            WriteZipEntry(archive, secondEntryName, secondContent);
        }

        return stream.ToArray();
    }

    private static void WriteZipEntry(ZipArchive archive, string entryName, string content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(entryName);
        using Stream entryStream = entry.Open();
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        entryStream.Write(bytes);
    }
}
