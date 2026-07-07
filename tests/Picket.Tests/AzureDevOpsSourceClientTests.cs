using System.Net;
using System.Text;
using Picket.Sources;

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
}
