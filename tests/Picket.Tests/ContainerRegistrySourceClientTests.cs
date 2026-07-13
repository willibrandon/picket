using Picket.Sources;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ZstdSharp;

namespace Picket.Tests;

/// <summary>
/// Tests pull-only OCI and Docker registry image enumeration.
/// </summary>
[TestClass]
public sealed class ContainerRegistrySourceClientTests
{
    private const string OciImageIndexMediaType = "application/vnd.oci.image.index.v1+json";
    private const string OciImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string OciLayerGzipMediaType = "application/vnd.oci.image.layer.v1.tar+gzip";
    private const string OciLayerMediaType = "application/vnd.oci.image.layer.v1.tar";
    private const string DockerLayerMediaType = "application/vnd.docker.image.rootfs.diff.tar";
    private const string OciNondistributableLayerZstandardMediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";
    private static readonly string[] s_unsafeBlobRedirects =
    [
        "http://cdn.example/layer",
        "https://registry-user@cdn.example/layer",
    ];

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies anonymous bearer exchange, all-platform traversal, shared-layer deduplication, and credential-free blob redirects.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesReadsAllPlatformsThroughBearerChallenge()
    {
        byte[] layer = CreateTarBytes("app/settings.txt", "registry-secret-value");
        string layerDigest = CreateDigest(layer);
        byte[] amd64Config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] arm64Config = Encoding.UTF8.GetBytes("{\"architecture\":\"arm64\",\"os\":\"linux\"}");
        byte[] amd64Manifest = CreateImageManifest(amd64Config, layer, OciLayerMediaType);
        byte[] arm64Manifest = CreateImageManifest(arm64Config, layer, OciLayerMediaType);
        byte[] index = CreateImageIndex(amd64Manifest, arm64Manifest);
        string amd64ManifestDigest = CreateDigest(amd64Manifest);
        string arm64ManifestDigest = CreateDigest(arm64Manifest);
        string amd64ConfigDigest = CreateDigest(amd64Config);
        string arm64ConfigDigest = CreateDigest(arm64Config);
        var requests = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            string authorization = request.Headers.Authorization?.ToString() ?? string.Empty;
            requests.Add(string.Concat(request.RequestUri!.AbsoluteUri, "|", authorization));
            string path = Uri.UnescapeDataString(request.RequestUri.AbsolutePath);
            if (request.RequestUri.Host.Equals("auth.example", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse("{\"token\":\"registry-token\"}");
            }

            if (request.RequestUri.Host.Equals("cdn.example", StringComparison.OrdinalIgnoreCase))
            {
                return BytesResponse(layer);
            }

            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal)
                && !authorization.Equals("Bearer registry-token", StringComparison.Ordinal))
            {
                return BearerChallengeResponse("https://auth.example/token", "registry.example");
            }

            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(index, OciImageIndexMediaType);
            }

            if (path.EndsWith(string.Concat("/manifests/", amd64ManifestDigest), StringComparison.Ordinal))
            {
                return ManifestResponse(amd64Manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/manifests/", arm64ManifestDigest), StringComparison.Ordinal))
            {
                return ManifestResponse(arm64Manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", amd64ConfigDigest), StringComparison.Ordinal))
            {
                return BlobResponse(amd64Config);
            }

            if (path.EndsWith(string.Concat("/blobs/", arm64ConfigDigest), StringComparison.Ordinal))
            {
                return BlobResponse(arm64Config);
            }

            if (path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.example/layer");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"));

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] paths = files.Select(static file => file.DisplayPath).ToArray();
        Assert.HasCount(6, files);
        Assert.Contains(static path => path.EndsWith("/index.json", StringComparison.Ordinal), paths);
        Assert.HasCount(2, paths.Where(static path => path.EndsWith("/manifest.json", StringComparison.Ordinal)));
        Assert.HasCount(2, paths.Where(static path => path.EndsWith("/config.json", StringComparison.Ordinal)));
        Assert.Contains(static path => path.EndsWith("!app/settings.txt", StringComparison.Ordinal), paths);
        SourceFile layerFile = files.Single(static file => file.DisplayPath.EndsWith("!app/settings.txt", StringComparison.Ordinal));
        Assert.AreEqual("registry-secret-value", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
        Assert.ContainsSingle(value => value.Contains(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal), requests);
        Assert.Contains(static value => value.StartsWith("https://auth.example/token?", StringComparison.Ordinal)
            && value.Contains("scope=repository%3Ateam%2Fapp%3Apull", StringComparison.Ordinal)
            && value.EndsWith('|'), requests);
        Assert.Contains("https://cdn.example/layer|", requests);
        Assert.DoesNotContain(static value => value.Contains("auth.example", StringComparison.Ordinal)
            && value.Contains("Basic ", StringComparison.Ordinal), requests);
    }

    /// <summary>
    /// Verifies an OCI platform filter prevents unrelated platform manifests and blobs from being requested.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesFiltersImageIndexByPlatform()
    {
        byte[] layer = CreateTarBytes("app/settings.txt", "platform-secret-value");
        byte[] amd64Config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] arm64Config = Encoding.UTF8.GetBytes("{\"architecture\":\"arm64\",\"os\":\"linux\"}");
        byte[] amd64Manifest = CreateImageManifest(amd64Config, layer, OciLayerMediaType);
        byte[] arm64Manifest = CreateImageManifest(arm64Config, layer, OciLayerMediaType);
        byte[] index = CreateImageIndex(amd64Manifest, arm64Manifest);
        string amd64ManifestDigest = CreateDigest(amd64Manifest);
        string arm64ManifestDigest = CreateDigest(arm64Manifest);
        string amd64ConfigDigest = CreateDigest(amd64Config);
        string layerDigest = CreateDigest(layer);
        var requests = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            requests.Add(path);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(index, OciImageIndexMediaType);
            }

            if (path.EndsWith(string.Concat("/manifests/", amd64ManifestDigest), StringComparison.Ordinal))
            {
                return ManifestResponse(amd64Manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", amd64ConfigDigest), StringComparison.Ordinal))
            {
                return BlobResponse(amd64Config);
            }

            if (path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal))
            {
                return BlobResponse(layer);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            platform: "linux/amd64");

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(4, files);
        Assert.DoesNotContain(value => value.EndsWith(string.Concat("/manifests/", arm64ManifestDigest), StringComparison.Ordinal), requests);
    }

    /// <summary>
    /// Verifies Docker schema 2 uncompressed layer media types are expanded.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesReadsDockerUncompressedLayer()
    {
        byte[] layer = CreateTarBytes("app/docker-secret.txt", "docker-uncompressed-value");

        List<SourceFile> files = await EnumerateSingleLayerImageAsync(layer, DockerLayerMediaType).ConfigureAwait(false);

        SourceFile layerFile = files.Single(static file => file.DisplayPath.EndsWith("!app/docker-secret.txt", StringComparison.Ordinal));
        Assert.AreEqual("docker-uncompressed-value", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies OCI nondistributable zstd layer media types are expanded.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesReadsOciNondistributableZstandardLayer()
    {
        byte[] layerTar = CreateTarBytes("app/zstd-secret.txt", "oci-zstandard-value");
        byte[] layer = CreateZstandardBytes(layerTar);

        List<SourceFile> files = await EnumerateSingleLayerImageAsync(
            layer,
            OciNondistributableLayerZstandardMediaType).ConfigureAwait(false);

        SourceFile layerFile = files.Single(static file => file.DisplayPath.EndsWith("!app/zstd-secret.txt", StringComparison.Ordinal));
        Assert.AreEqual("oci-zstandard-value", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies a failed config download does not hide a verified manifest or its layers when no platform lookup depends on it.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesContinuesWhenConfigIsUnavailable()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/config-independent.txt", "config-independent-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
        string layerDigest = CreateDigest(layer);
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                ? BlobResponse(layer)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"));

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(static file => file.DisplayPath.EndsWith("/manifest.json", StringComparison.Ordinal), files);
        SourceFile layerFile = files.Single(static file => file.DisplayPath.EndsWith("!app/config-independent.txt", StringComparison.Ordinal));
        Assert.AreEqual("config-independent-value", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
        Assert.DoesNotContain(static file => file.DisplayPath.EndsWith("/config.json", StringComparison.Ordinal), files);
    }

    /// <summary>
    /// Verifies image config platform metadata is not parsed when no platform filter is requested.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesSkipsConfigPlatformParseWithoutFilter()
    {
        byte[] config = Encoding.UTF8.GetBytes("not-json-platform-metadata");
        byte[] layer = CreateTarBytes("app/settings.txt", "layer-value");

        List<SourceFile> files = await EnumerateSingleLayerImageAsync(layer, OciLayerMediaType, config).ConfigureAwait(false);

        Assert.Contains(static file => file.DisplayPath.EndsWith("/config.json", StringComparison.Ordinal), files);
        SourceFile layerFile = files.Single(static file => file.DisplayPath.EndsWith("!app/settings.txt", StringComparison.Ordinal));
        Assert.AreEqual("layer-value", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies basic credentials are not sent to an untrusted cross-host token service.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsUntrustedBasicAuthenticationRealm()
    {
        const string Password = "registry-password";
        var warnings = new List<string>();
        var requestHosts = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            requestHosts.Add(request.RequestUri!.Host);
            return BearerChallengeResponse("https://login.attacker.example/token", "registry.example");
        });
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            credentialKind: ContainerRegistryCredentialKind.Basic,
            credential: Password,
            username: "picket-user",
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, requestHosts);
        Assert.AreEqual("registry.example", requestHosts[0]);
        Assert.Contains(static warning => warning.Contains("explicit authentication endpoint", StringComparison.Ordinal), warnings);
        Assert.DoesNotContain(Password, string.Join('\n', warnings));
    }

    /// <summary>
    /// Verifies token-service realms cannot override Picket's pull-only authentication query parameters.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsTokenRealmWithReservedScope()
    {
        var requestedHosts = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            requestedHosts.Add(request.RequestUri!.Host);
            return BearerChallengeResponse(
                "https://auth.example/token?%73cope=repository%3Ateam%2Fapp%3Apush",
                "registry.example");
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.HasCount(1, requestedHosts);
        Assert.AreEqual("registry.example", requestedHosts[0]);
        Assert.Contains(static warning => warning.Contains("reserved authentication query parameters", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies descriptor digest mismatches are rejected before layer content is reported.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsBlobDigestMismatch()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "digest-secret-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
        string configDigest = CreateDigest(config);
        byte[] wrongConfig = new byte[config.Length];
        wrongConfig.AsSpan().Fill((byte)'x');
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BytesResponse(wrongConfig);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(static file => file.DisplayPath.EndsWith("/manifest.json", StringComparison.Ordinal), files);
        Assert.DoesNotContain(static file => file.DisplayPath.EndsWith("/config.json", StringComparison.Ordinal), files);
        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains(static warning => warning.Contains("content digest did not match", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies ambiguous content-digest headers are rejected instead of selecting one value.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsAmbiguousContentDigestHeader()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "ambiguous-digest-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
        string configDigest = CreateDigest(config);
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (!path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            HttpResponseMessage response = BytesResponse(config);
            response.Headers.TryAddWithoutValidation(
                "Docker-Content-Digest",
                [configDigest, "sha256:0000000000000000000000000000000000000000000000000000000000000000"]);
            return response;
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(static file => file.DisplayPath.EndsWith("/manifest.json", StringComparison.Ordinal), files);
        Assert.DoesNotContain(static file => file.DisplayPath.EndsWith("/config.json", StringComparison.Ordinal), files);
        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains(static warning => warning.Contains("Docker-Content-Digest did not match", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies descriptor size mismatches are rejected even when content remains under the byte cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsBlobSizeMismatch()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "size-mismatch-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType, layerSize: 1);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                ? BlobResponse(layer)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains(static warning => warning.Contains("declared size did not match", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies layer redirects cannot downgrade transport security or carry URI user information.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsUnsafeBlobRedirects()
    {
        for (int i = 0; i < s_unsafeBlobRedirects.Length; i++)
        {
            byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
            byte[] layer = CreateTarBytes("app/settings.txt", "unsafe-redirect-value");
            byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
            string configDigest = CreateDigest(config);
            string layerDigest = CreateDigest(layer);
            var requestedHosts = new List<string>();
            var warnings = new List<string>();
            using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
            {
                requestedHosts.Add(request.RequestUri!.Host);
                string path = Uri.UnescapeDataString(request.RequestUri.AbsolutePath);
                if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
                {
                    return ManifestResponse(manifest, OciImageManifestMediaType);
                }

                if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
                {
                    return BlobResponse(config);
                }

                return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                    ? RedirectResponse(s_unsafeBlobRedirects[i])
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }));
            var client = new ContainerRegistrySourceClient(httpClient);
            var options = new ContainerRegistrySourceOptions(
                ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
                warningSink: warnings.Add);

            List<SourceFile> files = await client.EnumerateImageFilesAsync(
                options,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
            Assert.DoesNotContain("cdn.example", requestedHosts);
            Assert.Contains(static warning => warning.Contains("redirect target was not allowed", StringComparison.Ordinal), warnings);
        }
    }

    /// <summary>
    /// Verifies layer downloads follow at most one redirect.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesDoesNotFollowSecondBlobRedirect()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "redirect-chain-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        var requestedHosts = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            requestedHosts.Add(request.RequestUri!.Host);
            string path = Uri.UnescapeDataString(request.RequestUri.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            if (path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal))
            {
                return RedirectResponse("https://cdn.example/first");
            }

            return request.RequestUri.Host.Equals("cdn.example", StringComparison.OrdinalIgnoreCase)
                ? RedirectResponse("https://second.example/layer")
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"));

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains("cdn.example", requestedHosts);
        Assert.DoesNotContain("second.example", requestedHosts);
    }

    /// <summary>
    /// Verifies the streamed layer byte cap remains authoritative when Content-Length is understated.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesAppliesByteCapToUnderstatedContentLength()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", new string('x', 4096));
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType, layerSize: 1);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            if (path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal))
            {
                HttpResponseMessage response = BlobResponse(layer);
                response.Content.Headers.ContentLength = 1;
                return response;
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            maxBlobBytes: 128,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains(static warning => warning.Contains("image layer exceeded the byte limit", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies aggregate image bytes stop subsequent descriptor downloads before memory grows past the configured cap.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesAppliesAggregateImageByteCap()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "aggregate-secret-value");
        byte[] manifest = CreateImageManifest(config, layer, OciLayerMediaType);
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            return path.EndsWith("/manifests/latest", StringComparison.Ordinal)
                ? ManifestResponse(manifest, OciImageManifestMediaType)
                : BlobResponse(config);
        });
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            maxImageBytes: manifest.Length,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(static file => file.DisplayPath.EndsWith("/manifest.json", StringComparison.Ordinal), files);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains(static warning => warning.Contains("declared size exceeded a byte limit", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies unsupported manifest schema versions are rejected before descriptors are processed.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsUnsupportedManifestSchema()
    {
        byte[] manifest = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"}");
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(
            _ => ManifestResponse(manifest, OciImageManifestMediaType)));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains(static warning => warning.Contains("unsupported manifest schema", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies response and body media types must identify the same manifest kind.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsInconsistentManifestMediaType()
    {
        byte[] manifest = Encoding.UTF8.GetBytes(string.Concat(
            "{\"schemaVersion\":2,\"mediaType\":\"",
            OciImageIndexMediaType,
            "\",\"manifests\":[]}"));
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(
            _ => ManifestResponse(manifest, OciImageManifestMediaType)));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.Contains(static warning => warning.Contains("inconsistent manifest media type", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies a malformed child manifest does not prevent valid sibling manifests from being scanned.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesContinuesAfterMalformedChildManifest()
    {
        byte[] malformedManifest = "{"u8.ToArray();
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateTarBytes("app/settings.txt", "token-12345");
        byte[] validManifest = CreateImageManifest(config, layer, OciLayerMediaType);
        byte[] index = CreateImageIndex(
        [
            CreateManifestDescriptor(malformedManifest, OciImageManifestMediaType),
            CreateManifestDescriptor(validManifest, OciImageManifestMediaType),
        ]);
        string malformedDigest = CreateDigest(malformedManifest);
        string validDigest = CreateDigest(validManifest);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(index, OciImageIndexMediaType);
            }

            if (path.EndsWith(string.Concat("/manifests/", malformedDigest), StringComparison.Ordinal))
            {
                return ManifestResponse(malformedManifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/manifests/", validDigest), StringComparison.Ordinal))
            {
                return ManifestResponse(validManifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                ? BlobResponse(layer)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(
            static file => file.DisplayPath.EndsWith("!app/settings.txt", StringComparison.Ordinal)
                && Encoding.UTF8.GetString(file.ReadAllBytes()).Equals("token-12345", StringComparison.Ordinal),
            files);
        Assert.Contains(
            static warning => warning.Contains("skipped manifest", StringComparison.Ordinal)
                && warning.Contains("invalid or unavailable", StringComparison.Ordinal),
            warnings);
    }

    /// <summary>
    /// Verifies recursive image indexes stop at the manifest nesting limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesStopsAtManifestNestingLimit()
    {
        byte[][] indexes = new byte[6][];
        indexes[^1] = CreateImageIndex(Array.Empty<string>());
        for (int i = indexes.Length - 2; i >= 0; i--)
        {
            indexes[i] = CreateImageIndex([CreateManifestDescriptor(indexes[i + 1], OciImageIndexMediaType)]);
        }

        Dictionary<string, byte[]> manifestsByDigest = indexes.ToDictionary(CreateDigest, static value => value);
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(indexes[0], OciImageIndexMediaType);
            }

            string digest = path[(path.LastIndexOf('/') + 1)..];
            return manifestsByDigest.TryGetValue(digest, out byte[]? manifest)
                ? ManifestResponse(manifest, OciImageIndexMediaType)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(5, files);
        Assert.AreEqual(6, handler.RequestCount);
        Assert.Contains(static warning => warning.Contains("manifest nesting exceeded", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies image indexes stop enumerating descriptors at the configured count limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesStopsAtIndexManifestCountLimit()
    {
        string[] descriptors = Enumerable.Repeat(
            "{}",
            ContainerRegistrySourceOptions.MaxIndexManifestCount + 1).ToArray();
        byte[] index = CreateImageIndex(descriptors);
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(_ => ManifestResponse(index, OciImageIndexMediaType));
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(static file => file.DisplayPath.EndsWith("/index.json", StringComparison.Ordinal), files);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains(static warning => warning.Contains("manifest descriptor limit", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies image manifests reject layer arrays beyond the configured count limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesRejectsExcessiveLayerCount()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] manifest = CreateImageManifestWithLayerCount(
            config,
            ContainerRegistrySourceOptions.MaxLayerCount + 1);
        var warnings = new List<string>();
        var handler = new FakeHttpMessageHandler(_ => ManifestResponse(manifest, OciImageManifestMediaType));
        using var httpClient = new HttpClient(handler);
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(files);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains(static warning => warning.Contains("layer count safety limit", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies layer expansion applies the configured archive compression-ratio limit.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesAppliesArchiveCompressionRatioLimit()
    {
        byte[] config = Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] layer = CreateGzipBytes(CreateTarBytes("app/settings.txt", new string('a', 200_000)));
        byte[] manifest = CreateImageManifest(config, layer, OciLayerGzipMediaType);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                ? BlobResponse(layer)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            maxArchiveCompressionRatio: 2,
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(static file => file.DisplayPath.Contains('!'), files);
        Assert.Contains(static warning => warning.Contains("archive compression ratio limit reached", StringComparison.Ordinal), warnings);
    }

    /// <summary>
    /// Verifies an explicit authentication endpoint receives Basic credentials and returns the pull bearer token.
    /// </summary>
    [TestMethod]
    public async Task EnumerateImageFilesUsesExplicitBasicAuthenticationEndpoint()
    {
        const string Password = "registry-password";
        const string Username = "picket-user";
        byte[] manifest = Encoding.UTF8.GetBytes(
            "{\"schemaVersion\":1,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"}");
        var requests = new List<string>();
        var warnings = new List<string>();
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string authorization = request.Headers.Authorization?.ToString() ?? string.Empty;
            requests.Add(string.Concat(request.RequestUri!.Host, "|", authorization));
            if (request.RequestUri.Host.Equals("auth.example", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse("{\"token\":\"registry-token\"}");
            }

            return authorization.Equals("Bearer registry-token", StringComparison.Ordinal)
                ? ManifestResponse(manifest, OciImageManifestMediaType)
                : BearerChallengeResponse("https://untrusted.example/token", "registry.example");
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"),
            credentialKind: ContainerRegistryCredentialKind.Basic,
            credential: Password,
            username: Username,
            authenticationEndpoint: new Uri("https://auth.example/token"),
            warningSink: warnings.Add);

        List<SourceFile> files = await client.EnumerateImageFilesAsync(
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        string expectedBasicAuthorization = string.Concat(
            "Basic ",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(Username, ":", Password))));
        Assert.IsEmpty(files);
        Assert.Contains(string.Concat("auth.example|", expectedBasicAuthorization), requests);
        Assert.Contains("registry.example|Bearer registry-token", requests);
        Assert.DoesNotContain(static request => request.StartsWith("untrusted.example|", StringComparison.Ordinal), requests);
        Assert.DoesNotContain(Password, string.Join('\n', warnings));
    }

    private static byte[] CreateImageManifest(
        byte[] config,
        byte[] layer,
        string layerMediaType,
        long? layerSize = null)
    {
        string json = string.Concat(
            "{\"schemaVersion\":2,\"mediaType\":\"",
            OciImageManifestMediaType,
            "\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"",
            CreateDigest(config),
            "\",\"size\":",
            config.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "},\"layers\":[{\"mediaType\":\"",
            layerMediaType,
            "\",\"digest\":\"",
            CreateDigest(layer),
            "\",\"size\":",
            (layerSize ?? layer.Length).ToString(System.Globalization.CultureInfo.InvariantCulture),
            "}]}"
        );
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] CreateImageManifestWithLayerCount(byte[] config, int layerCount)
    {
        string json = string.Concat(
            "{\"schemaVersion\":2,\"mediaType\":\"",
            OciImageManifestMediaType,
            "\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"",
            CreateDigest(config),
            "\",\"size\":",
            config.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "},\"layers\":[",
            string.Join(',', Enumerable.Repeat("{}", layerCount)),
            "]}"
        );
        return Encoding.UTF8.GetBytes(json);
    }

    private async Task<List<SourceFile>> EnumerateSingleLayerImageAsync(
        byte[] layer,
        string layerMediaType,
        byte[]? config = null)
    {
        config ??= Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        byte[] manifest = CreateImageManifest(config, layer, layerMediaType);
        string configDigest = CreateDigest(config);
        string layerDigest = CreateDigest(layer);
        using var httpClient = new HttpClient(new FakeHttpMessageHandler(request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith("/manifests/latest", StringComparison.Ordinal))
            {
                return ManifestResponse(manifest, OciImageManifestMediaType);
            }

            if (path.EndsWith(string.Concat("/blobs/", configDigest), StringComparison.Ordinal))
            {
                return BlobResponse(config);
            }

            return path.EndsWith(string.Concat("/blobs/", layerDigest), StringComparison.Ordinal)
                ? BlobResponse(layer)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var client = new ContainerRegistrySourceClient(httpClient);
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app:latest"));

        return await client.EnumerateImageFilesAsync(options, TestContext.CancellationToken).ConfigureAwait(false);
    }

    private static byte[] CreateZstandardBytes(byte[] content)
    {
        using var stream = new MemoryStream();
        using (var compressionStream = new CompressionStream(stream, leaveOpen: true))
        {
            compressionStream.Write(content);
        }

        return stream.ToArray();
    }

    private static byte[] CreateGzipBytes(byte[] content)
    {
        using var stream = new MemoryStream();
        using (var compressionStream = new GZipStream(stream, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            compressionStream.Write(content);
        }

        return stream.ToArray();
    }

    private static byte[] CreateImageIndex(string[] descriptors)
    {
        string json = string.Concat(
            "{\"schemaVersion\":2,\"mediaType\":\"",
            OciImageIndexMediaType,
            "\",\"manifests\":[",
            string.Join(',', descriptors),
            "]}"
        );
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] CreateImageIndex(byte[] amd64Manifest, byte[] arm64Manifest)
    {
        string json = string.Concat(
            "{\"schemaVersion\":2,\"mediaType\":\"",
            OciImageIndexMediaType,
            "\",\"manifests\":[",
            CreateIndexDescriptor(amd64Manifest, "amd64"),
            ",",
            CreateIndexDescriptor(arm64Manifest, "arm64"),
            "]}"
        );
        return Encoding.UTF8.GetBytes(json);
    }

    private static string CreateIndexDescriptor(byte[] manifest, string architecture)
    {
        return string.Concat(
            "{\"mediaType\":\"",
            OciImageManifestMediaType,
            "\",\"digest\":\"",
            CreateDigest(manifest),
            "\",\"size\":",
            manifest.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ",\"platform\":{\"architecture\":\"",
            architecture,
            "\",\"os\":\"linux\"}}"
        );
    }

    private static string CreateManifestDescriptor(byte[] manifest, string mediaType)
    {
        return string.Concat(
            "{\"mediaType\":\"",
            mediaType,
            "\",\"digest\":\"",
            CreateDigest(manifest),
            "\",\"size\":",
            manifest.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "}"
        );
    }

    private static byte[] CreateTarBytes(string entryName, string content)
    {
        using var stream = new MemoryStream();
        using (var writer = new TarWriter(stream, leaveOpen: true))
        {
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            using var contentStream = new MemoryStream(contentBytes, writable: false);
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = contentStream,
            };
            writer.WriteEntry(entry);
        }

        return stream.ToArray();
    }

    private static string CreateDigest(byte[] content)
    {
        return string.Concat("sha256:", Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content)));
    }

    private static HttpResponseMessage BearerChallengeResponse(string realm, string service)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(
            "Bearer",
            string.Concat("realm=\"", realm, "\",service=\"", service, "\",scope=\"repository:ignored:push,pull\"")));
        return response;
    }

    private static HttpResponseMessage JsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage ManifestResponse(byte[] content, string mediaType)
    {
        HttpResponseMessage response = BytesResponse(content, mediaType);
        response.Headers.TryAddWithoutValidation("Docker-Content-Digest", CreateDigest(content));
        return response;
    }

    private static HttpResponseMessage BlobResponse(byte[] content)
    {
        HttpResponseMessage response = BytesResponse(content);
        response.Headers.TryAddWithoutValidation("Docker-Content-Digest", CreateDigest(content));
        return response;
    }

    private static HttpResponseMessage BytesResponse(
        byte[] content,
        string mediaType = "application/octet-stream")
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(content),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return response;
    }

    private static HttpResponseMessage RedirectResponse(string location)
    {
        return new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
        {
            Headers = { Location = new Uri(location) },
        };
    }
}
