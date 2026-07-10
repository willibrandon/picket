using Picket.Sources;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Azure Artifacts package source enumeration.
/// </summary>
[TestClass]
public sealed class AzureDevOpsPackageSourceClientTests
{
    private static readonly string[] s_unsafeRedirectUris =
    [
        "http://picket.blob.core.windows.net/package.nupkg",
        "https://user@picket.blob.core.windows.net/package.nupkg",
    ];
    private static readonly string s_fullPackagePageJson = CreateFullPackagePageJson();

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that Azure DevOps Services endpoints map to the documented Artifacts service hosts.
    /// </summary>
    [TestMethod]
    public void SourceOptionsDerivesAzureArtifactsServiceEndpoints()
    {
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            includePackages: true);

        Assert.AreEqual("https://feeds.dev.azure.com/picket/", options.ArtifactsEndpoint.AbsoluteUri);
        Assert.AreEqual("https://pkgs.dev.azure.com/picket/", options.PackageContentEndpoint.AbsoluteUri);
        Assert.AreEqual(100_000_000, options.MaxPackageBytes);
    }

    /// <summary>
    /// Verifies that package selectors cannot silently do nothing when package enumeration is disabled.
    /// </summary>
    [TestMethod]
    public void SourceOptionsRequiresPackageEnumerationForPackageSelectors()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            feed: "release"));
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            includePackages: true,
            packageVersion: "1.2.3"));
        Assert.ThrowsExactly<ArgumentException>(() => new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            maxPackageBytes: 1));
    }

    /// <summary>
    /// Verifies that feed enumeration downloads and expands the latest NuGet package version.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesReadsLatestNuGetPackage()
    {
        var requestUris = new List<string>();
        var authorizationHeaders = new List<string>();
        byte[] packageContent = CreateZipBytes("content/appsettings.json", "package-token-1234");
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            requestUris.Add(request.RequestUri!.AbsoluteUri);
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            string path = request.RequestUri.AbsolutePath;
            if (path.EndsWith("/_apis/packaging/feeds", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse("""{"value":[{"id":"feed-id","name":"release"}]}""");
            }

            if (path.EndsWith("/_apis/packaging/Feeds/feed-id/packages", StringComparison.Ordinal))
            {
                return JsonResponse("""
                    {"value":[{"id":"package-id","name":"Picket.Sample","protocolType":"NuGet","versions":[{"version":"1.2.3","normalizedVersion":"1.2.3","isLatest":true}]}]}
                    """);
            }

            if (path.EndsWith("/_apis/packaging/feeds/feed-id/nuget/packages/Picket.Sample/versions/1.2.3/content", StringComparison.Ordinal))
            {
                return BinaryResponse(packageContent);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            project: "test",
            includePackages: true);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual(
            "azure-devops/test/artifacts/release/Picket.Sample/1.2.3/Picket.Sample.nupkg!content/appsettings.json",
            files[0].DisplayPath);
        Assert.AreEqual("package-token-1234", Encoding.UTF8.GetString(files[0].ReadAllBytes()));
        Assert.HasCount(3, requestUris);
        Assert.Contains("protocolType=NuGet", requestUris[1]);
        Assert.Contains("%24top=100", requestUris[1]);
        Assert.IsTrue(authorizationHeaders.All(static value => value.StartsWith("Basic ", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Verifies that an exact package version can be downloaded without package metadata enumeration.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesReadsExactVersionDirectly()
    {
        var requestUris = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            requestUris.Add(request.RequestUri!.AbsoluteUri);
            return BinaryResponse(Encoding.UTF8.GetBytes("not-an-archive-token"));
        }));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            project: "test",
            includePackages: true,
            feed: "release",
            package: "Picket.Sample",
            packageVersion: "2.0.0");

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.HasCount(1, requestUris);
        Assert.Contains("/feeds/release/nuget/packages/Picket.Sample/versions/2.0.0/content", requestUris[0]);
    }

    /// <summary>
    /// Verifies that package download redirects do not receive Azure DevOps credentials.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesStripsAuthorizationFromDownloadRedirect()
    {
        var authorizationHeaders = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            authorizationHeaders.Add(request.Headers.Authorization?.ToString() ?? string.Empty);
            if (request.RequestUri!.Host.Equals("pkgs.dev.azure.com", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = new Uri("https://picket.blob.core.windows.net/package.nupkg?signature=redacted") },
                };
            }

            return BinaryResponse(Encoding.UTF8.GetBytes("redirected-package-token"));
        }));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            includePackages: true,
            feed: "release",
            package: "Picket.Sample",
            packageVersion: "2.0.0");

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.HasCount(2, authorizationHeaders);
        Assert.IsTrue(authorizationHeaders[0].StartsWith("Basic ", StringComparison.Ordinal));
        Assert.IsEmpty(authorizationHeaders[1]);
    }

    /// <summary>
    /// Verifies that package redirects outside Azure DevOps artifact hosts are rejected before another request is sent.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesRejectsRedirectOutsideAzureDevOpsArtifactHosts()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(static _ => RedirectResponse("https://downloads.example/package.nupkg"));
        using var httpClient = new HttpClient(handler);
        var client = new AzureDevOpsPackageSourceClient(httpClient);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(
            CreateExactPackageOptions(warnings.Add),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("download redirect is not an allowed Azure DevOps artifact endpoint", warnings[0]);
    }

    /// <summary>
    /// Verifies that insecure and userinfo-bearing package redirects are rejected.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesRejectsInsecureDownloadRedirect()
    {
        for (int i = 0; i < s_unsafeRedirectUris.Length; i++)
        {
            var warnings = new List<string>();
            string redirectUri = s_unsafeRedirectUris[i];
            var handler = new FakeHttpMessageHandler(_ => RedirectResponse(redirectUri));
            using var httpClient = new HttpClient(handler);
            var client = new AzureDevOpsPackageSourceClient(httpClient);

            List<SourceFile> files = await client.EnumeratePackageFilesAsync(
                CreateExactPackageOptions(warnings.Add),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(files);
            Assert.AreEqual(1, handler.RequestCount);
            Assert.HasCount(1, warnings);
            Assert.Contains("download redirect is not an allowed Azure DevOps artifact endpoint", warnings[0]);
        }
    }

    /// <summary>
    /// Verifies that a redirected package response cannot initiate a second redirect hop.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesDoesNotFollowSecondRedirectHop()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request => request.RequestUri!.Host.Equals("pkgs.dev.azure.com", StringComparison.OrdinalIgnoreCase)
            ? RedirectResponse("https://picket.blob.core.windows.net/first.nupkg")
            : RedirectResponse("https://picket.blob.core.windows.net/second.nupkg"));
        using var httpClient = new HttpClient(handler);
        var client = new AzureDevOpsPackageSourceClient(httpClient);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(
            CreateExactPackageOptions(warnings.Add),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps returned 302", warnings[0]);
    }

    /// <summary>
    /// Verifies that redirected package bodies remain subject to the configured byte cap.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesAppliesByteCapToRedirectedDownload()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request => request.RequestUri!.Host.Equals("pkgs.dev.azure.com", StringComparison.OrdinalIgnoreCase)
            ? RedirectResponse("https://picket.blob.core.windows.net/package.nupkg")
            : StreamingBinaryResponse(9));
        using var httpClient = new HttpClient(handler);
        var client = new AzureDevOpsPackageSourceClient(httpClient);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(
            CreateExactPackageOptions(warnings.Add, maxPackageBytes: 4),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(2, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure Artifacts package byte limit skipped", warnings[0]);
    }

    /// <summary>
    /// Verifies that responses from handlers that already followed a package redirect are rejected.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesBlocksAutoFollowedDownloadRedirects()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(static _ => AutoRedirectedBinaryResponse(
            "package-token",
            "https://picket.blob.core.windows.net/package.nupkg"));
        using var httpClient = new HttpClient(handler);
        var client = new AzureDevOpsPackageSourceClient(httpClient);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(
            CreateExactPackageOptions(warnings.Add),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure DevOps returned 421", warnings[0]);
    }

    /// <summary>
    /// Verifies that provider-controlled feed, package, and version names cannot create unsafe display paths.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesNormalizesUnsafeDisplayPathSegments()
    {
        int requestCount = 0;
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(_ => ++requestCount switch
        {
            1 => JsonResponse("""{"value":[{"id":"feed-id","name":".."}]}"""),
            2 => JsonResponse("""{"value":[{"name":"a\\b","protocolType":"NuGet","versions":[{"version":"../1","isLatest":true}]}]}"""),
            _ => BinaryResponse(Encoding.UTF8.GetBytes("package-token")),
        }));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            project: "test",
            includePackages: true);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, files);
        Assert.AreEqual("azure-devops/test/artifacts/_/a_b/.._1/a_b.nupkg", files[0].DisplayPath);
        Assert.DoesNotContain("\\", files[0].DisplayPath);
        Assert.DoesNotContain("/../", files[0].DisplayPath);
    }

    /// <summary>
    /// Verifies that package enumeration stops at its bounded pagination ceiling.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task EnumeratePackageFilesStopsAtPaginationSafetyLimit()
    {
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(_ => JsonResponse(s_fullPackagePageJson));
        using var httpClient = new HttpClient(handler);
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warnings.Add,
            includePackages: true,
            feed: "release");

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1000, handler.RequestCount);
        Assert.HasCount(1, warnings);
        Assert.Contains("pagination safety limit", warnings[0]);
    }

    /// <summary>
    /// Verifies that package downloads stop at the configured byte ceiling.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesRejectsPackageExceedingByteCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => BinaryResponse(Encoding.UTF8.GetBytes("too-large"))));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warnings.Add,
            includePackages: true,
            feed: "release",
            package: "Picket.Sample",
            packageVersion: "2.0.0",
            maxPackageBytes: 4);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure Artifacts package byte limit skipped", warnings[0]);
        Assert.DoesNotContain("token", warnings[0]);
    }

    /// <summary>
    /// Verifies that the package cap applies to streamed bodies without a declared content length.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesRejectsStreamedPackageExceedingByteCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => StreamingBinaryResponse(9)));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warnings.Add,
            includePackages: true,
            feed: "release",
            package: "Picket.Sample",
            packageVersion: "2.0.0",
            maxPackageBytes: 4);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure Artifacts package byte limit skipped", warnings[0]);
        Assert.DoesNotContain("token", warnings[0]);
    }

    /// <summary>
    /// Verifies that Azure Artifacts metadata is rejected before reading a declared oversized response.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesRejectsMetadataResponseExceedingCap()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => OversizedMetadataResponse()));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warnings.Add,
            includePackages: true);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.Contains("Azure Artifacts feed metadata", warnings[0]);
        Assert.Contains("exceeding the 10000000 byte metadata cap", warnings[0]);
        Assert.DoesNotContain("token", warnings[0]);
    }

    /// <summary>
    /// Verifies that malformed provider metadata produces a bounded warning instead of escaping the source client.
    /// </summary>
    [TestMethod]
    public async Task EnumeratePackageFilesWarnsForMalformedFeedMetadata()
    {
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(static _ => JsonResponse("{")));
        var client = new AzureDevOpsPackageSourceClient(httpClient);
        var options = new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warnings.Add,
            includePackages: true);

        List<SourceFile> files = await client.EnumeratePackageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, warnings);
        Assert.AreEqual("skipping Azure Artifacts packages because feed metadata was invalid", warnings[0]);
        Assert.DoesNotContain("token", warnings[0]);
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage BinaryResponse(byte[] content)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(content),
        };
    }

    private static HttpResponseMessage StreamingBinaryResponse(int length)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatingReadStream(length, (byte)'x')),
        };
    }

    private static HttpResponseMessage RedirectResponse(string location)
    {
        return new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri(location) },
        };
    }

    private static HttpResponseMessage AutoRedirectedBinaryResponse(string content, string redirectedUri)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content)),
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, redirectedUri),
        };
    }

    private static AzureDevOpsSourceOptions CreateExactPackageOptions(
        Action<string>? warningSink = null,
        long? maxPackageBytes = null)
    {
        return new AzureDevOpsSourceOptions(
            AzureDevOpsSourceOptions.CreateServicesEndpoint("picket"),
            "token",
            warningSink: warningSink,
            includePackages: true,
            feed: "release",
            package: "Picket.Sample",
            packageVersion: "2.0.0",
            maxPackageBytes: maxPackageBytes);
    }

    private static string CreateFullPackagePageJson()
    {
        var builder = new StringBuilder("{\"value\":[");
        for (int i = 0; i < 100; i++)
        {
            if (i != 0)
            {
                builder.Append(',');
            }

            builder.Append("{}");
        }

        builder.Append("]}");
        return builder.ToString();
    }

    private static HttpResponseMessage OversizedMetadataResponse()
    {
        HttpResponseMessage response = JsonResponse("{}");
        response.Content.Headers.ContentLength = RemoteJsonDocumentReader.DefaultMaxMetadataBytes + 1;
        return response;
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
