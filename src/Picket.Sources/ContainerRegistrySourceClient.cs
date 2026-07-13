using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates configuration and layer files from pull-only OCI and Docker registry image references.
/// </summary>
/// <param name="httpClient">The guarded HTTP client used for registry and token-service requests.</param>
public sealed class ContainerRegistrySourceClient(HttpClient httpClient)
{
    private const string DockerImageManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json";
    private const string DockerImageIndexMediaType = "application/vnd.docker.distribution.manifest.list.v2+json";
    private const string DockerLayerGzipMediaType = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    private const string DockerLayerMediaType = "application/vnd.docker.image.rootfs.diff.tar";
    private const string DockerForeignLayerGzipMediaType = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";
    private const string OciImageIndexMediaType = "application/vnd.oci.image.index.v1+json";
    private const string OciImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string OciLayerGzipMediaType = "application/vnd.oci.image.layer.v1.tar+gzip";
    private const string OciLayerMediaType = "application/vnd.oci.image.layer.v1.tar";
    private const string OciLayerZstandardMediaType = "application/vnd.oci.image.layer.v1.tar+zstd";
    private const string OciNondistributableLayerGzipMediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";
    private const string OciNondistributableLayerMediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar";
    private const string OciNondistributableLayerZstandardMediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";
    private const int MaxAuthenticationResponseBytes = 1_000_000;
    private const int MaxManifestDepth = 4;
    private const string ManifestAcceptHeader = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-container-registry");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Pulls the selected image manifests and blobs and returns bounded source files for scanning.
    /// </summary>
    /// <param name="options">The registry source options.</param>
    /// <param name="cancellationToken">A token that cancels registry requests and layer processing.</param>
    /// <returns>The source files selected from the image.</returns>
    public async Task<List<SourceFile>> EnumerateImageFilesAsync(
        ContainerRegistrySourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var session = new ContainerRegistrySession(options);
        try
        {
            (byte[] Content, string MediaType)? rootManifest = await DownloadManifestAsync(
                session,
                options.Image.Reference,
                options.Image.IsDigest ? options.Image.Reference : null,
                expectedSize: null,
                cancellationToken).ConfigureAwait(false);
            if (!rootManifest.HasValue)
            {
                return session.Files;
            }

            string rootDigest = CreateSha256Digest(rootManifest.Value.Content);
            session.BaseDisplayPath = CreateBaseDisplayPath(options, rootDigest);
            await ProcessManifestAsync(
                session,
                rootManifest.Value.Content,
                rootManifest.Value.MediaType,
                rootDigest,
                platformHint: string.Empty,
                manifestDepth: 0,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or JsonException)
        {
            options.WarningSink?.Invoke("container registry image enumeration stopped because the registry response was invalid or unavailable");
        }

        return session.Files;
    }

    private async Task ProcessManifestAsync(
        ContainerRegistrySession session,
        byte[] content,
        string responseMediaType,
        string digest,
        string platformHint,
        int manifestDepth,
        CancellationToken cancellationToken)
    {
        if (IsCancellationRequested(session.Options) || manifestDepth > MaxManifestDepth)
        {
            if (manifestDepth > MaxManifestDepth)
            {
                session.Options.WarningSink?.Invoke("container registry manifest nesting exceeded the safety limit");
            }

            return;
        }

        if (!session.ManifestDigests.Add(digest))
        {
            return;
        }

        if (session.ManifestDigests.Count > ContainerRegistrySourceOptions.MaxIndexManifestCount)
        {
            session.Options.WarningSink?.Invoke("container registry manifest count exceeded the safety limit");
            return;
        }

        using JsonDocument document = JsonDocument.Parse(content);
        JsonElement root = document.RootElement;
        if (!TryGetInt32(root, "schemaVersion", out int schemaVersion) || schemaVersion != 2)
        {
            session.Options.WarningSink?.Invoke("container registry returned an unsupported manifest schema");
            return;
        }

        string bodyMediaType = GetOptionalString(root, "mediaType");
        string mediaType = ResolveManifestMediaType(responseMediaType, bodyMediaType);
        if (mediaType.Length == 0)
        {
            session.Options.WarningSink?.Invoke("container registry returned an unsupported or inconsistent manifest media type");
            return;
        }

        if (IsImageIndexMediaType(mediaType))
        {
            AddSourceFile(session, CreateManifestDisplayPath(session, digest, "index.json"), content);
            await ProcessImageIndexAsync(
                session,
                root,
                manifestDepth,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await ProcessImageManifestAsync(
            session,
            root,
            content,
            digest,
            platformHint,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ProcessImageIndexAsync(
        ContainerRegistrySession session,
        JsonElement root,
        int manifestDepth,
        CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("manifests", out JsonElement manifests)
            || manifests.ValueKind != JsonValueKind.Array)
        {
            session.Options.WarningSink?.Invoke("container registry image index did not contain a manifest list");
            return;
        }

        int descriptorCount = 0;
        int selectedCount = 0;
        foreach (JsonElement descriptor in manifests.EnumerateArray())
        {
            if (IsCancellationRequested(session.Options))
            {
                return;
            }

            descriptorCount++;
            if (descriptorCount > ContainerRegistrySourceOptions.MaxIndexManifestCount)
            {
                session.Options.WarningSink?.Invoke("container registry image index exceeded the manifest descriptor limit");
                break;
            }

            string platform = GetDescriptorPlatform(descriptor);
            if (!MatchesPlatform(session.Options.Platform, platform)
                || !TryReadDescriptor(descriptor, out string digest, out long size, out string mediaType)
                || !IsManifestMediaType(mediaType))
            {
                continue;
            }

            selectedCount++;
            if (!CanDownloadDescriptor(session, size, ContainerRegistrySourceOptions.MaxManifestBytes, "manifest"))
            {
                continue;
            }

            try
            {
                (byte[] Content, string MediaType)? manifest = await DownloadManifestAsync(
                    session,
                    digest,
                    digest,
                    size,
                    cancellationToken).ConfigureAwait(false);
                if (!manifest.HasValue)
                {
                    continue;
                }

                await ProcessManifestAsync(
                    session,
                    manifest.Value.Content,
                    manifest.Value.MediaType,
                    digest,
                    platform,
                    manifestDepth + 1,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or JsonException)
            {
                session.Options.WarningSink?.Invoke(
                    $"container registry skipped manifest {ShortDigest(digest)} because its response was invalid or unavailable");
            }
        }

        if (session.Options.Platform.Length != 0 && selectedCount == 0)
        {
            session.Options.WarningSink?.Invoke($"container registry image index did not contain platform {session.Options.Platform}");
        }
    }

    private async Task ProcessImageManifestAsync(
        ContainerRegistrySession session,
        JsonElement root,
        byte[] manifestContent,
        string manifestDigest,
        string platformHint,
        CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("config", out JsonElement configDescriptor)
            || !TryReadDescriptor(configDescriptor, out string configDigest, out long configSize, out _)
            || !root.TryGetProperty("layers", out JsonElement layers)
            || layers.ValueKind != JsonValueKind.Array)
        {
            session.Options.WarningSink?.Invoke("container registry image manifest did not contain valid config and layer descriptors");
            return;
        }

        if (layers.GetArrayLength() > ContainerRegistrySourceOptions.MaxLayerCount)
        {
            session.Options.WarningSink?.Invoke("container registry image manifest exceeded the layer count safety limit");
            return;
        }

        byte[]? configContent = await DownloadBlobAsync(
            session,
            configDigest,
            configSize,
            "image config",
            cancellationToken).ConfigureAwait(false);
        if (configContent is null)
        {
            if (session.Options.Platform.Length != 0 && platformHint.Length == 0)
            {
                return;
            }

            AddSourceFile(
                session,
                CreateManifestDisplayPath(session, manifestDigest, "manifest.json"),
                manifestContent);
        }
        else
        {
            if (session.Options.Platform.Length != 0)
            {
                if (configContent.LongLength > ContainerRegistrySourceOptions.MaxManifestBytes)
                {
                    session.Options.WarningSink?.Invoke("container registry image config exceeded the platform metadata safety limit");
                    return;
                }

                string resolvedPlatform = platformHint.Length == 0 ? GetConfigPlatform(configContent) : platformHint;
                if (!MatchesPlatform(session.Options.Platform, resolvedPlatform))
                {
                    session.Options.WarningSink?.Invoke($"container registry image manifest did not match platform {session.Options.Platform}");
                    return;
                }
            }

            AddSourceFile(
                session,
                CreateManifestDisplayPath(session, manifestDigest, "manifest.json"),
                manifestContent);
            AddSourceFile(
                session,
                CreateBlobDisplayPath(session, configDigest, "config.json"),
                configContent);
        }

        int layerIndex = 0;
        foreach (JsonElement layerDescriptor in layers.EnumerateArray())
        {
            if (IsCancellationRequested(session.Options))
            {
                return;
            }

            layerIndex++;
            if (!TryReadDescriptor(layerDescriptor, out string layerDigest, out long layerSize, out string layerMediaType))
            {
                session.Options.WarningSink?.Invoke($"container registry skipped invalid layer descriptor {layerIndex.ToString(CultureInfo.InvariantCulture)}");
                continue;
            }

            if (!IsSupportedLayerMediaType(layerMediaType))
            {
                session.Options.WarningSink?.Invoke($"container registry skipped layer {ShortDigest(layerDigest)} with unsupported media type");
                continue;
            }

            if (session.ExpandedLayerDigests.Contains(layerDigest))
            {
                continue;
            }

            byte[]? layerContent = await DownloadBlobAsync(
                session,
                layerDigest,
                layerSize,
                "image layer",
                cancellationToken).ConfigureAwait(false);
            if (layerContent is null)
            {
                continue;
            }

            ExpandLayer(session, layerDigest, layerMediaType, layerContent);
            if (session.ExpandedLayerDigests.Contains(layerDigest))
            {
                session.BlobContent.Remove(layerDigest);
                CryptographicOperations.ZeroMemory(layerContent);
            }
        }
    }

    private async Task<(byte[] Content, string MediaType)?> DownloadManifestAsync(
        ContainerRegistrySession session,
        string reference,
        string? expectedDigest,
        long? expectedSize,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateManifestUri(session.Options, reference);
        using HttpResponseMessage response = await SendRegistryRequestAsync(
            session,
            uri,
            ManifestAcceptHeader,
            cancellationToken).ConfigureAwait(false);
        ReportRegistryWarningHeaders(session, response);
        if (!response.IsSuccessStatusCode)
        {
            WarnStatus(session.Options, response, "container registry manifest request failed");
            return null;
        }

        byte[]? content = await ReadImageContentAsync(
            session,
            response,
            ContainerRegistrySourceOptions.MaxManifestBytes,
            "container registry manifest",
            cancellationToken).ConfigureAwait(false);
        if (content is null
            || expectedSize.HasValue && content.LongLength != expectedSize.Value
            || !VerifyContentDigests(session.Options, response, content, expectedDigest, "manifest"))
        {
            if (content is not null && expectedSize.HasValue && content.LongLength != expectedSize.Value)
            {
                session.Options.WarningSink?.Invoke("container registry rejected manifest because its declared size did not match the response body");
            }

            return null;
        }

        return (content, response.Content.Headers.ContentType?.MediaType ?? string.Empty);
    }

    private async Task<byte[]?> DownloadBlobAsync(
        ContainerRegistrySession session,
        string digest,
        long declaredSize,
        string target,
        CancellationToken cancellationToken)
    {
        if (session.BlobContent.TryGetValue(digest, out byte[]? cachedContent))
        {
            return cachedContent;
        }

        if (!CanDownloadDescriptor(session, declaredSize, session.Options.MaxBlobBytes, target))
        {
            return null;
        }

        Uri uri = CreateBlobUri(session.Options, digest);
        using HttpResponseMessage response = await SendRegistryRequestAsync(
            session,
            uri,
            "application/octet-stream",
            cancellationToken).ConfigureAwait(false);
        ReportRegistryWarningHeaders(session, response);
        HttpResponseMessage? redirectedResponse = null;
        try
        {
            HttpResponseMessage contentResponse = response;
            if (IsRedirect(response) && response.Headers.Location is not null)
            {
                Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location
                    : new Uri(uri, response.Headers.Location);
                if (!IsSafeBlobRedirect(session.Options, redirectUri))
                {
                    session.Options.WarningSink?.Invoke($"container registry skipped {target} because its redirect target was not allowed");
                    return null;
                }

                redirectedResponse = IsSameOrigin(session.Options.Endpoint, redirectUri)
                    ? await SendRegistryRequestAsync(session, redirectUri, "application/octet-stream", cancellationToken).ConfigureAwait(false)
                    : await SendUnauthenticatedAsync(redirectUri, "application/octet-stream", cancellationToken).ConfigureAwait(false);
                contentResponse = redirectedResponse;
                ReportRegistryWarningHeaders(session, contentResponse);
            }

            if (!contentResponse.IsSuccessStatusCode)
            {
                WarnStatus(session.Options, contentResponse, $"container registry {target} request failed");
                return null;
            }

            byte[]? content = await ReadImageContentAsync(
                session,
                contentResponse,
                session.Options.MaxBlobBytes,
                $"container registry {target}",
                cancellationToken).ConfigureAwait(false);
            if (content is null
                || content.LongLength != declaredSize
                || !VerifyContentDigests(session.Options, contentResponse, content, digest, target))
            {
                if (content is not null && content.LongLength != declaredSize)
                {
                    session.Options.WarningSink?.Invoke($"container registry rejected {target} because its declared size did not match the response body");
                }

                return null;
            }

            session.BlobContent.Add(digest, content);
            return content;
        }
        finally
        {
            redirectedResponse?.Dispose();
        }
    }

    private async Task<HttpResponseMessage> SendRegistryRequestAsync(
        ContainerRegistrySession session,
        Uri uri,
        string accept,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response = await SendRegistryRequestCoreAsync(
            session,
            uri,
            accept,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized
            || !ContainerRegistryBearerChallenge.TryCreate(response, out ContainerRegistryBearerChallenge? challenge))
        {
            return response;
        }

        string? bearerToken;
        try
        {
            bearerToken = await AcquireBearerTokenAsync(
                session,
                challenge,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            response.Dispose();
            throw;
        }
        if (bearerToken is null)
        {
            return response;
        }

        response.Dispose();
        session.BearerToken = bearerToken;
        return await SendRegistryRequestCoreAsync(session, uri, accept, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendRegistryRequestCoreAsync(
        ContainerRegistrySession session,
        Uri uri,
        string accept,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.TryAddWithoutValidation("Accept", accept);
                AuthenticationHeaderValue? authorization = CreateRegistryAuthorization(session);
                if (authorization is not null)
                {
                    request.Headers.Authorization = authorization;
                }

                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendUnauthenticatedAsync(
        Uri uri,
        string accept,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.TryAddWithoutValidation("Accept", accept);
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<string?> AcquireBearerTokenAsync(
        ContainerRegistrySession session,
        ContainerRegistryBearerChallenge challenge,
        CancellationToken cancellationToken)
    {
        ContainerRegistrySourceOptions options = session.Options;
        Uri tokenEndpoint = options.AuthenticationEndpoint ?? challenge.Realm;
        if (!IsSafeTokenEndpoint(options, tokenEndpoint))
        {
            options.WarningSink?.Invoke("container registry rejected an unsafe token-service endpoint");
            return null;
        }

        if (HasReservedTokenQueryParameter(tokenEndpoint))
        {
            options.WarningSink?.Invoke("container registry rejected a token-service endpoint with reserved authentication query parameters");
            return null;
        }

        if (options.CredentialKind == ContainerRegistryCredentialKind.Basic
            && options.AuthenticationEndpoint is null
            && !IsTrustedCredentialRealm(options.Endpoint, tokenEndpoint))
        {
            options.WarningSink?.Invoke("container registry requires an explicit authentication endpoint before credentials can be sent to a cross-host token service");
            return null;
        }

        Uri tokenUri = CreateTokenUri(tokenEndpoint, challenge.Service, options.Image.Repository);
        using HttpResponseMessage response = await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, tokenUri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                if (options.CredentialKind == ContainerRegistryCredentialKind.Basic)
                {
                    request.Headers.Authorization = CreateBasicAuthorization(options.Username, options.Credential);
                }

                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
        ReportRegistryWarningHeaders(session, response);
        if (!response.IsSuccessStatusCode)
        {
            WarnStatus(options, response, "container registry token request failed");
            return null;
        }

        byte[]? content = await ReadBoundedContentAsync(
            response,
            MaxAuthenticationResponseBytes,
            "container registry token response exceeded the byte limit",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (content is null)
        {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(content);
        string token = GetOptionalString(document.RootElement, "token");
        if (token.Length == 0)
        {
            token = GetOptionalString(document.RootElement, "access_token");
        }

        if (!ContainerRegistrySourceOptions.IsValidBearerToken(token))
        {
            options.WarningSink?.Invoke("container registry token response did not contain a valid bearer token");
            return null;
        }

        return token;
    }

    private static AuthenticationHeaderValue? CreateRegistryAuthorization(ContainerRegistrySession session)
    {
        if (session.BearerToken.Length != 0)
        {
            return new AuthenticationHeaderValue("Bearer", session.BearerToken);
        }

        return session.Options.CredentialKind == ContainerRegistryCredentialKind.Basic
            ? CreateBasicAuthorization(session.Options.Username, session.Options.Credential)
            : null;
    }

    private static AuthenticationHeaderValue CreateBasicAuthorization(string username, string credential)
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(username, ":", credential)));
        return new AuthenticationHeaderValue("Basic", encoded);
    }

    private static async Task<byte[]?> ReadImageContentAsync(
        ContainerRegistrySession session,
        HttpResponseMessage response,
        long objectLimit,
        string target,
        CancellationToken cancellationToken)
    {
        long remainingImageBytes = session.Options.MaxImageBytes - session.DownloadedBytes;
        if (remainingImageBytes <= 0)
        {
            session.Options.WarningSink?.Invoke("container registry image byte limit was reached");
            return null;
        }

        long effectiveLimit = Math.Min(objectLimit, remainingImageBytes);
        byte[]? content = await ReadBoundedContentAsync(
            response,
            effectiveLimit,
            string.Concat(target, " exceeded the byte limit"),
            session.Options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (content is not null)
        {
            session.DownloadedBytes += content.Length;
        }

        return content;
    }

    private static async Task<byte[]?> ReadBoundedContentAsync(
        HttpResponseMessage response,
        long maxBytes,
        string warning,
        Action<string>? warningSink,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > maxBytes)
        {
            warningSink?.Invoke(warning);
            return null;
        }

        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            while (true)
            {
                int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (memory.Length > maxBytes - read)
                {
                    warningSink?.Invoke(warning);
                    return null;
                }

                memory.Write(buffer, 0, read);
            }

            return memory.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static void ExpandLayer(
        ContainerRegistrySession session,
        string digest,
        string mediaType,
        byte[] content)
    {
        ContainerRegistrySourceOptions options = session.Options;
        if (options.MaxArchiveDepth <= 0)
        {
            return;
        }

        if (options.MaxArchiveEntries != 0 && session.ExtractedEntryCount >= options.MaxArchiveEntries)
        {
            options.WarningSink?.Invoke("container registry image layer entry limit was reached");
            return;
        }

        long? remainingArchiveBytes = options.MaxArchiveBytes;
        if (remainingArchiveBytes.HasValue && remainingArchiveBytes.Value != 0)
        {
            remainingArchiveBytes = remainingArchiveBytes.Value - session.ExtractedByteCount;
            if (remainingArchiveBytes <= 0)
            {
                options.WarningSink?.Invoke("container registry image layer decompressed byte limit was reached");
                return;
            }
        }

        int remainingEntries = options.MaxArchiveEntries == 0
            ? 0
            : options.MaxArchiveEntries - session.ExtractedEntryCount;
        string displayPath = CreateBlobDisplayPath(session, digest, GetLayerFileName(mediaType));
        var entries = new List<ArchiveEntry>();
        if (!ArchiveReader.TryReadBytesEntries(
            content,
            displayPath,
            options.MaxArchiveDepth,
            remainingEntries,
            remainingArchiveBytes,
            options.MaxArchiveCompressionRatio,
            options.MaxTargetBytes,
            options.IsPathAllowed,
            options.WarningSink,
            options.IsCancellationRequested,
            entries))
        {
            options.WarningSink?.Invoke($"container registry skipped layer {ShortDigest(digest)} because its archive format was invalid or unsupported");
            return;
        }

        session.ExpandedLayerDigests.Add(digest);
        for (int i = 0; i < entries.Count; i++)
        {
            ArchiveEntry entry = entries[i];
            session.ExtractedEntryCount++;
            session.ExtractedByteCount += entry.Content.Length;
            session.Files.Add(new SourceFile(s_remoteFullPath, entry.DisplayPath, entry.Content));
        }
    }

    private static bool CanDownloadDescriptor(
        ContainerRegistrySession session,
        long declaredSize,
        long objectLimit,
        string target)
    {
        if (declaredSize < 0
            || declaredSize > objectLimit
            || declaredSize > session.Options.MaxImageBytes - session.DownloadedBytes)
        {
            session.Options.WarningSink?.Invoke($"container registry skipped {target} because its declared size exceeded a byte limit");
            return false;
        }

        return true;
    }

    private static bool VerifyContentDigests(
        ContainerRegistrySourceOptions options,
        HttpResponseMessage response,
        byte[] content,
        string? expectedDigest,
        string target)
    {
        if (expectedDigest is not null && !MatchesSha256Digest(content, expectedDigest))
        {
            options.WarningSink?.Invoke($"container registry rejected {target} because its content digest did not match the descriptor");
            return false;
        }

        if (!TryGetDockerContentDigest(response, out string headerDigest))
        {
            return true;
        }

        if (!ContainerRegistryImageReference.TryParseSha256Digest(headerDigest, out _)
            || !MatchesSha256Digest(content, headerDigest))
        {
            options.WarningSink?.Invoke($"container registry rejected {target} because Docker-Content-Digest did not match the response body");
            return false;
        }

        return true;
    }

    private static bool MatchesSha256Digest(byte[] content, string digest)
    {
        if (!ContainerRegistryImageReference.TryParseSha256Digest(digest, out byte[] expectedBytes))
        {
            return false;
        }

        byte[] actualBytes = SHA256.HashData(content);
        return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
    }

    private static bool TryGetDockerContentDigest(HttpResponseMessage response, out string digest)
    {
        digest = string.Empty;
        if (!response.Headers.TryGetValues("Docker-Content-Digest", out IEnumerable<string>? values))
        {
            return false;
        }

        bool found = false;
        foreach (string value in values)
        {
            if (found || value.Contains(','))
            {
                digest = string.Empty;
                return true;
            }

            digest = value.Trim();
            found = true;
        }

        return found;
    }

    private static bool TryReadDescriptor(
        JsonElement descriptor,
        out string digest,
        out long size,
        out string mediaType)
    {
        digest = GetOptionalString(descriptor, "digest");
        mediaType = GetOptionalString(descriptor, "mediaType");
        size = -1;
        return ContainerRegistryImageReference.TryParseSha256Digest(digest, out _)
            && descriptor.TryGetProperty("size", out JsonElement sizeElement)
            && sizeElement.ValueKind == JsonValueKind.Number
            && sizeElement.TryGetInt64(out size)
            && size >= 0;
    }

    private static string ResolveManifestMediaType(string responseMediaType, string bodyMediaType)
    {
        string normalizedResponse = NormalizeMediaType(responseMediaType);
        string normalizedBody = NormalizeMediaType(bodyMediaType);
        bool responseSupported = IsManifestMediaType(normalizedResponse);
        bool bodySupported = IsManifestMediaType(normalizedBody);
        if (responseSupported && bodySupported)
        {
            return normalizedResponse.Equals(normalizedBody, StringComparison.OrdinalIgnoreCase)
                ? normalizedResponse
                : string.Empty;
        }

        if (bodySupported)
        {
            return normalizedBody;
        }

        return responseSupported ? normalizedResponse : string.Empty;
    }

    private static string NormalizeMediaType(string value)
    {
        int separator = value.IndexOf(';', StringComparison.Ordinal);
        return (separator < 0 ? value : value[..separator]).Trim();
    }

    private static bool IsManifestMediaType(string value)
    {
        return IsImageManifestMediaType(value) || IsImageIndexMediaType(value);
    }

    private static bool IsImageManifestMediaType(string value)
    {
        return value.Equals(OciImageManifestMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(DockerImageManifestMediaType, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsImageIndexMediaType(string value)
    {
        return value.Equals(OciImageIndexMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(DockerImageIndexMediaType, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSupportedLayerMediaType(string value)
    {
        return value.Equals(OciLayerMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(OciLayerGzipMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(OciLayerZstandardMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(OciNondistributableLayerMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(OciNondistributableLayerGzipMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(OciNondistributableLayerZstandardMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(DockerLayerMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(DockerLayerGzipMediaType, StringComparison.OrdinalIgnoreCase)
            || value.Equals(DockerForeignLayerGzipMediaType, StringComparison.OrdinalIgnoreCase);
    }

    private static string GetLayerFileName(string mediaType)
    {
        if (mediaType.EndsWith("+gzip", StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals(DockerLayerGzipMediaType, StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals(DockerForeignLayerGzipMediaType, StringComparison.OrdinalIgnoreCase))
        {
            return "layer.tar.gz";
        }

        return mediaType.EndsWith("+zstd", StringComparison.OrdinalIgnoreCase)
            ? "layer.tar.zst"
            : "layer.tar";
    }

    private static string GetDescriptorPlatform(JsonElement descriptor)
    {
        if (!descriptor.TryGetProperty("platform", out JsonElement platform)
            || platform.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return CreatePlatform(
            GetOptionalString(platform, "os"),
            GetOptionalString(platform, "architecture"),
            GetOptionalString(platform, "variant"));
    }

    private static string GetConfigPlatform(byte[] content)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(content);
            return CreatePlatform(
                GetOptionalString(document.RootElement, "os"),
                GetOptionalString(document.RootElement, "architecture"),
                GetOptionalString(document.RootElement, "variant"));
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    private static string CreatePlatform(string operatingSystem, string architecture, string variant)
    {
        if (operatingSystem.Length == 0 || architecture.Length == 0)
        {
            return string.Empty;
        }

        string value = variant.Length == 0
            ? string.Concat(operatingSystem, "/", architecture)
            : string.Concat(operatingSystem, "/", architecture, "/", variant);
        try
        {
            return ContainerRegistrySourceOptions.NormalizePlatform(value);
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
    }

    private static bool MatchesPlatform(string filter, string platform)
    {
        if (filter.Length == 0)
        {
            return true;
        }

        if (platform.Length == 0)
        {
            return false;
        }

        if (filter.Equals(platform, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        int filterSegments = CountSegments(filter);
        return filterSegments == 2
            && platform.StartsWith(string.Concat(filter, "/"), StringComparison.OrdinalIgnoreCase);
    }

    private static int CountSegments(string value)
    {
        int count = 1;
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '/')
            {
                count++;
            }
        }

        return count;
    }

    private static string GetOptionalString(JsonElement value, string propertyName)
    {
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }

    private static bool TryGetInt32(JsonElement value, string propertyName, out int result)
    {
        result = 0;
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt32(out result);
    }

    private static Uri CreateManifestUri(ContainerRegistrySourceOptions options, string reference)
    {
        return CreateRegistryUri(options, "manifests", reference);
    }

    private static Uri CreateBlobUri(ContainerRegistrySourceOptions options, string digest)
    {
        return CreateRegistryUri(options, "blobs", digest);
    }

    private static Uri CreateRegistryUri(
        ContainerRegistrySourceOptions options,
        string resource,
        string value)
    {
        string endpoint = options.Endpoint.AbsoluteUri.TrimEnd('/');
        var builder = new StringBuilder(endpoint);
        builder.Append("/v2/");
        AppendEscapedRepository(builder, options.Image.Repository);
        builder.Append('/');
        builder.Append(resource);
        builder.Append('/');
        builder.Append(Uri.EscapeDataString(value).Replace("%3A", ":", StringComparison.OrdinalIgnoreCase));
        return new Uri(builder.ToString(), UriKind.Absolute);
    }

    private static void AppendEscapedRepository(StringBuilder builder, string repository)
    {
        ReadOnlySpan<char> remaining = repository;
        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOf('/');
            ReadOnlySpan<char> segment = separator < 0 ? remaining : remaining[..separator];
            builder.Append(Uri.EscapeDataString(segment));
            if (separator < 0)
            {
                return;
            }

            builder.Append('/');
            remaining = remaining[(separator + 1)..];
        }
    }

    private static Uri CreateTokenUri(Uri endpoint, string service, string repository)
    {
        var builder = new UriBuilder(endpoint);
        var query = new StringBuilder(builder.Query.TrimStart('?'));
        AppendQueryParameter(query, "client_id", "picket");
        if (service.Length != 0)
        {
            AppendQueryParameter(query, "service", service);
        }

        AppendQueryParameter(query, "scope", string.Concat("repository:", repository, ":pull"));
        builder.Query = query.ToString();
        return builder.Uri;
    }

    private static void AppendQueryParameter(StringBuilder builder, string name, string value)
    {
        if (builder.Length != 0)
        {
            builder.Append('&');
        }

        builder.Append(Uri.EscapeDataString(name));
        builder.Append('=');
        builder.Append(Uri.EscapeDataString(value));
    }

    private static bool IsSafeTokenEndpoint(ContainerRegistrySourceOptions options, Uri endpoint)
    {
        return endpoint.IsAbsoluteUri
            && string.IsNullOrEmpty(endpoint.UserInfo)
            && string.IsNullOrEmpty(endpoint.Fragment)
            && (endpoint.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || options.AllowInsecureCredentialTransport
                && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasReservedTokenQueryParameter(Uri endpoint)
    {
        ReadOnlySpan<char> remaining = endpoint.Query.AsSpan().TrimStart('?');
        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOfAny('&', ';');
            ReadOnlySpan<char> parameter = separator < 0 ? remaining : remaining[..separator];
            int equals = parameter.IndexOf('=');
            ReadOnlySpan<char> encodedName = equals < 0 ? parameter : parameter[..equals];
            string name;
            try
            {
                name = Uri.UnescapeDataString(encodedName.ToString().Replace('+', ' '));
            }
            catch (UriFormatException)
            {
                return true;
            }

            if (name.Equals("client_id", StringComparison.OrdinalIgnoreCase)
                || name.Equals("scope", StringComparison.OrdinalIgnoreCase)
                || name.Equals("service", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (separator < 0)
            {
                break;
            }

            remaining = remaining[(separator + 1)..];
        }

        return false;
    }

    private static bool IsTrustedCredentialRealm(Uri registryEndpoint, Uri tokenEndpoint)
    {
        if (tokenEndpoint.Host.Equals(registryEndpoint.Host, StringComparison.OrdinalIgnoreCase)
            || tokenEndpoint.Host.EndsWith(string.Concat(".", registryEndpoint.Host), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return registryEndpoint.Host.Equals("registry-1.docker.io", StringComparison.OrdinalIgnoreCase)
            && tokenEndpoint.Host.Equals("auth.docker.io", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSafeBlobRedirect(ContainerRegistrySourceOptions options, Uri uri)
    {
        return uri.IsAbsoluteUri
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Fragment)
            && (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || options.AllowInsecureCredentialTransport
                && uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSameOrigin(Uri left, Uri right)
    {
        return left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase)
            && left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase)
            && left.Port == right.Port;
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        return response.StatusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Redirect
            or HttpStatusCode.RedirectMethod
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
    }

    private static string CreateBaseDisplayPath(
        ContainerRegistrySourceOptions options,
        string rootDigest)
    {
        string referencePath = options.Image.IsDigest
            ? DigestPath(options.Image.Reference)
            : string.Concat("tags/", NormalizeDisplaySegment(options.Image.Reference));
        return string.Concat(
            "registry/",
            NormalizeDisplaySegment(options.Image.RegistryHost),
            "/",
            options.Image.Repository,
            "/",
            referencePath,
            "/resolved/",
            DigestPath(rootDigest));
    }

    private static string CreateManifestDisplayPath(
        ContainerRegistrySession session,
        string digest,
        string fileName)
    {
        return string.Concat(session.BaseDisplayPath, "/manifests/", DigestPath(digest), "/", fileName);
    }

    private static string CreateBlobDisplayPath(
        ContainerRegistrySession session,
        string digest,
        string fileName)
    {
        return string.Concat(session.BaseDisplayPath, "/blobs/", DigestPath(digest), "/", fileName);
    }

    private static string DigestPath(string digest)
    {
        return string.Concat("sha256/", digest.AsSpan(7));
    }

    private static string ShortDigest(string digest)
    {
        return digest.Length <= 19 ? digest : digest[..19];
    }

    private static string NormalizeDisplaySegment(string value)
    {
        string normalized = value.Replace('/', '_').Replace('\\', '_').Replace(':', '_');
        return normalized.Length == 0 || normalized is "." or ".."
            ? "_"
            : Uri.EscapeDataString(normalized);
    }

    private static void AddSourceFile(
        ContainerRegistrySession session,
        string displayPath,
        byte[] content)
    {
        if (content.LongLength > session.Options.MaxTargetBytes
            || session.Options.IsPathAllowed?.Invoke(displayPath) == true
            || !session.SourceDisplayPaths.Add(displayPath))
        {
            return;
        }

        session.Files.Add(new SourceFile(s_remoteFullPath, displayPath, content));
    }

    private static string CreateSha256Digest(byte[] content)
    {
        return string.Concat("sha256:", Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    private static void WarnStatus(
        ContainerRegistrySourceOptions options,
        HttpResponseMessage response,
        string prefix)
    {
        options.WarningSink?.Invoke(string.Concat(
            prefix,
            " with HTTP status ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture)));
    }

    private static void ReportRegistryWarningHeaders(
        ContainerRegistrySession session,
        HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Warning", out IEnumerable<string>? values))
        {
            return;
        }

        foreach (string _ in values)
        {
            const string Warning = "container registry returned an informational Warning header; its untrusted text was omitted from diagnostics";
            if (session.ReportedRegistryWarnings.Add(Warning))
            {
                session.Options.WarningSink?.Invoke(Warning);
            }

            return;
        }
    }

    private static bool IsCancellationRequested(ContainerRegistrySourceOptions options)
    {
        return options.IsCancellationRequested?.Invoke() == true;
    }
}
