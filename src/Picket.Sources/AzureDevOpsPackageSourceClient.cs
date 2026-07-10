using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Azure Artifacts NuGet package content through Azure DevOps REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for Azure Artifacts requests.</param>
public sealed class AzureDevOpsPackageSourceClient(HttpClient httpClient)
{
    private const string ApiVersion = "7.1";
    private const string PackageContentApiVersion = "7.1-preview.1";
    private const int MaxPages = 1000;
    private const int PageSize = 100;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-azure-devops-packages");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Azure Artifacts NuGet package files selected by the supplied options.
    /// </summary>
    /// <param name="options">The Azure DevOps source options.</param>
    /// <param name="cancellationToken">A token that can cancel package enumeration.</param>
    /// <returns>The selected package files and expanded archive entries.</returns>
    public async Task<List<SourceFile>> EnumeratePackageFilesAsync(
        AzureDevOpsSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (!options.IncludePackages || IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        List<(string Id, string Name)> feeds;
        try
        {
            feeds = options.Feed.Length == 0
                ? await ListFeedsAsync(options, cancellationToken).ConfigureAwait(false)
                : [(options.Feed, options.Feed)];
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }
        catch (JsonException)
        {
            options.WarningSink?.Invoke("skipping Azure Artifacts packages because feed metadata was invalid");
            return sourceFiles;
        }
        catch (HttpRequestException)
        {
            options.WarningSink?.Invoke("skipping Azure Artifacts packages because feed enumeration failed");
            return sourceFiles;
        }

        for (int i = 0; i < feeds.Count && !IsCancellationRequested(options); i++)
        {
            (string feedId, string feedName) = feeds[i];
            try
            {
                if (options.PackageVersion.Length != 0)
                {
                    await AddPackageVersionAsync(
                        options,
                        feedId,
                        feedName,
                        options.Package,
                        options.PackageVersion,
                        sourceFiles,
                        cancellationToken).ConfigureAwait(false);
                    continue;
                }

                await AddLatestPackagesAsync(
                    options,
                    feedId,
                    feedName,
                    sourceFiles,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (RemoteMetadataTooLargeException)
            {
                continue;
            }
            catch (JsonException)
            {
                options.WarningSink?.Invoke($"skipping Azure Artifacts feed {NormalizeDisplaySegment(feedName)} because package metadata was invalid");
            }
            catch (HttpRequestException)
            {
                options.WarningSink?.Invoke($"skipping Azure Artifacts feed {NormalizeDisplaySegment(feedName)} because package enumeration failed");
            }
        }

        return sourceFiles;
    }

    private async Task<List<(string Id, string Name)>> ListFeedsAsync(
        AzureDevOpsSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateFeedsUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, "skipping Azure Artifacts feeds");
            return [];
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            "Azure Artifacts feed metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var feeds = new List<(string Id, string Name)>();
        foreach (JsonElement feed in values.EnumerateArray())
        {
            if (!TryGetJsonString(feed, "id", out string id)
                || !TryGetJsonString(feed, "name", out string name))
            {
                continue;
            }

            feeds.Add((id, name));
        }

        return feeds;
    }

    private async Task AddLatestPackagesAsync(
        AzureDevOpsSourceOptions options,
        string feedId,
        string feedName,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int skip = 0;
        for (int page = 0; page < MaxPages && !IsCancellationRequested(options); page++)
        {
            Uri uri = CreatePackagesUri(options, feedId, skip);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Azure Artifacts feed {NormalizeDisplaySegment(feedName)}");
                return;
            }

            int packageCount = await AddPackagesAsync(
                options,
                feedId,
                feedName,
                response,
                sourceFiles,
                cancellationToken).ConfigureAwait(false);
            if (packageCount < PageSize)
            {
                return;
            }

            skip += packageCount;
        }

        if (!IsCancellationRequested(options))
        {
            options.WarningSink?.Invoke($"Azure Artifacts feed {NormalizeDisplaySegment(feedName)} package enumeration stopped at the pagination safety limit");
        }
    }

    private async Task<int> AddPackagesAsync(
        AzureDevOpsSourceOptions options,
        string feedId,
        string feedName,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            $"Azure Artifacts feed {NormalizeDisplaySegment(feedName)} package metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int packageCount = 0;
        foreach (JsonElement package in values.EnumerateArray())
        {
            packageCount++;
            if (IsCancellationRequested(options)
                || !TryGetJsonString(package, "name", out string packageName)
                || !TryGetJsonString(package, "protocolType", out string protocolType)
                || !protocolType.Equals("NuGet", StringComparison.OrdinalIgnoreCase)
                || options.Package.Length != 0 && !packageName.Equals(options.Package, StringComparison.OrdinalIgnoreCase)
                || !TryGetLatestVersion(package, out string packageVersion))
            {
                continue;
            }

            await AddPackageVersionAsync(
                options,
                feedId,
                feedName,
                packageName,
                packageVersion,
                sourceFiles,
                cancellationToken).ConfigureAwait(false);
        }

        return packageCount;
    }

    private async Task AddPackageVersionAsync(
        AzureDevOpsSourceOptions options,
        string feedId,
        string feedName,
        string packageName,
        string packageVersion,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string displayPath = CreatePackageDisplayPath(options, feedName, packageName, packageVersion);
        if (options.IsPathAllowed?.Invoke(displayPath) == true)
        {
            return;
        }

        Uri uri = CreatePackageContentUri(options, feedId, packageName, packageVersion);
        byte[]? content = await DownloadPackageAsync(options, uri, displayPath, cancellationToken).ConfigureAwait(false);
        if (content is null)
        {
            return;
        }

        AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
    }

    private async Task<byte[]?> DownloadPackageAsync(
        AzureDevOpsSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: false, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsSafePackageRedirect(redirectUri))
            {
                options.WarningSink?.Invoke($"skipping Azure Artifacts package {displayPath} because its download redirect is not a credential-free HTTPS endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping Azure Artifacts package {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, options, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure Artifacts package {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        AzureDevOpsSourceOptions options,
        Uri uri,
        bool acceptJson,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptJson ? "application/json" : "application/octet-stream"));
                request.Headers.Authorization = CreateAuthorizationHeader(options);
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendUnauthenticatedAsync(Uri uri, CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static AuthenticationHeaderValue CreateAuthorizationHeader(AzureDevOpsSourceOptions options)
    {
        if (options.CredentialKind == AzureDevOpsCredentialKind.BearerToken)
        {
            return new AuthenticationHeaderValue("Bearer", options.Credential);
        }

        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(":", options.Credential)));
        return new AuthenticationHeaderValue("Basic", encoded);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        AzureDevOpsSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxPackageBytes)
        {
            options.WarningSink?.Invoke($"Azure Artifacts package byte limit skipped {displayPath}");
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

                if (memory.Length + read > options.MaxPackageBytes)
                {
                    options.WarningSink?.Invoke($"Azure Artifacts package byte limit skipped {displayPath}");
                    return null;
                }

                memory.Write(buffer.AsSpan(0, read));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        return memory.ToArray();
    }

    private static void AddContentOrArchiveEntries(
        AzureDevOpsSourceOptions options,
        string displayPath,
        byte[] content,
        List<SourceFile> sourceFiles)
    {
        if (!ArchiveReader.IsArchiveContent(content))
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            return;
        }

        if (options.MaxArchiveDepth == 0)
        {
            options.WarningSink?.Invoke($"skipping Azure Artifacts package {displayPath} because archive traversal is disabled");
            return;
        }

        var entries = new List<ArchiveEntry>();
        if (!ArchiveReader.TryReadBytesEntries(
            content,
            displayPath,
            options.MaxArchiveDepth,
            options.MaxArchiveEntries,
            options.MaxArchiveBytes,
            options.MaxArchiveCompressionRatio,
            options.MaxFileBytes,
            options.IsPathAllowed,
            options.WarningSink,
            options.IsCancellationRequested,
            entries))
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            return;
        }

        for (int i = 0; i < entries.Count; i++)
        {
            ArchiveEntry entry = entries[i];
            sourceFiles.Add(new SourceFile(s_remoteFullPath, entry.DisplayPath, entry.Content));
        }
    }

    private static Uri CreateFeedsUri(AzureDevOpsSourceOptions options)
    {
        List<string> segments = CreateArtifactsScopeSegments(options);
        segments.Add("_apis");
        segments.Add("packaging");
        segments.Add("feeds");
        return CreateUri(options.ArtifactsEndpoint, segments, [new KeyValuePair<string, string>("api-version", ApiVersion)]);
    }

    private static Uri CreatePackagesUri(AzureDevOpsSourceOptions options, string feedId, int skip)
    {
        List<string> segments = CreateArtifactsScopeSegments(options);
        segments.Add("_apis");
        segments.Add("packaging");
        segments.Add("Feeds");
        segments.Add(feedId);
        segments.Add("packages");
        var query = new List<KeyValuePair<string, string>>
        {
            new("protocolType", "NuGet"),
            new("includeUrls", "false"),
            new("includeAllVersions", "false"),
            new("$top", PageSize.ToString(CultureInfo.InvariantCulture)),
            new("$skip", skip.ToString(CultureInfo.InvariantCulture)),
            new("api-version", ApiVersion),
        };
        if (options.Package.Length != 0)
        {
            query.Insert(1, new KeyValuePair<string, string>("packageNameQuery", options.Package));
        }

        return CreateUri(options.ArtifactsEndpoint, segments, query);
    }

    private static Uri CreatePackageContentUri(
        AzureDevOpsSourceOptions options,
        string feedId,
        string packageName,
        string packageVersion)
    {
        List<string> segments = CreateArtifactsScopeSegments(options);
        segments.Add("_apis");
        segments.Add("packaging");
        segments.Add("feeds");
        segments.Add(feedId);
        segments.Add("nuget");
        segments.Add("packages");
        segments.Add(packageName);
        segments.Add("versions");
        segments.Add(packageVersion);
        segments.Add("content");
        return CreateUri(
            options.PackageContentEndpoint,
            segments,
            [new KeyValuePair<string, string>("api-version", PackageContentApiVersion)]);
    }

    private static List<string> CreateArtifactsScopeSegments(AzureDevOpsSourceOptions options)
    {
        return options.Project.Length == 0 ? [] : [options.Project];
    }

    private static Uri CreateUri(
        Uri endpoint,
        IReadOnlyList<string> pathSegments,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CombinePath(endpoint.AbsolutePath, pathSegments),
            Query = CreateQuery(query),
        };
        return builder.Uri;
    }

    private static string CombinePath(string basePath, IReadOnlyList<string> segments)
    {
        var builder = new StringBuilder(basePath.TrimEnd('/'));
        for (int i = 0; i < segments.Count; i++)
        {
            builder.Append('/');
            builder.Append(Uri.EscapeDataString(segments[i]));
        }

        return builder.Length == 0 ? "/" : builder.ToString();
    }

    private static string CreateQuery(IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new StringBuilder();
        for (int i = 0; i < query.Count; i++)
        {
            if (i != 0)
            {
                builder.Append('&');
            }

            builder.Append(Uri.EscapeDataString(query[i].Key));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(query[i].Value));
        }

        return builder.ToString();
    }

    private static string CreatePackageDisplayPath(
        AzureDevOpsSourceOptions options,
        string feedName,
        string packageName,
        string packageVersion)
    {
        string project = options.Project.Length == 0 ? "organization" : NormalizeDisplaySegment(options.Project);
        string normalizedPackageName = NormalizeDisplaySegment(packageName);
        return string.Join(
            '/',
            "azure-devops",
            project,
            "artifacts",
            NormalizeDisplaySegment(feedName),
            normalizedPackageName,
            NormalizeDisplaySegment(packageVersion),
            string.Concat(normalizedPackageName, ".nupkg"));
    }

    private static string NormalizeDisplaySegment(string value)
    {
        string normalized = value.Replace('/', '_').Replace('\\', '_');
        if (normalized.Length == 0 || normalized is "." or "..")
        {
            return "_";
        }

        return Uri.EscapeDataString(normalized);
    }

    private static bool TryGetLatestVersion(JsonElement package, out string version)
    {
        version = string.Empty;
        if (!package.TryGetProperty("versions", out JsonElement versions)
            || versions.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in versions.EnumerateArray())
        {
            if (item.TryGetProperty("isLatest", out JsonElement isLatest)
                && isLatest.ValueKind == JsonValueKind.True
                && TryGetPackageVersion(item, out version))
            {
                return true;
            }

            if (version.Length == 0)
            {
                TryGetPackageVersion(item, out version);
            }
        }

        return version.Length != 0;
    }

    private static bool TryGetPackageVersion(JsonElement value, out string version)
    {
        return TryGetJsonString(value, "normalizedVersion", out version)
            || TryGetJsonString(value, "version", out version);
    }

    private static bool TryGetJsonString(JsonElement value, string propertyName, out string propertyValue)
    {
        propertyValue = string.Empty;
        if (!value.TryGetProperty(propertyName, out JsonElement property)
            || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        propertyValue = property.GetString() ?? string.Empty;
        return propertyValue.Length != 0;
    }

    private static bool IsSafePackageRedirect(Uri uri)
    {
        return uri.IsAbsoluteUri
            && uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(uri.UserInfo);
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        return response.StatusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Redirect
            or HttpStatusCode.RedirectMethod
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
    }

    private static bool IsCancellationRequested(AzureDevOpsSourceOptions options)
    {
        return options.IsCancellationRequested?.Invoke() == true;
    }

    private static void WarnUnsuccessfulResponse(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Azure DevOps returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }
}
