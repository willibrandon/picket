using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Google Cloud Storage objects through the Cloud Storage JSON API.
/// </summary>
/// <param name="httpClient">The HTTP client used for Cloud Storage requests.</param>
public sealed class GcsSourceClient(HttpClient httpClient)
{
    private const int ListObjectsMaxResults = 1000;
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-gcs-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Google Cloud Storage objects selected by the supplied options.
    /// </summary>
    /// <param name="options">The GCS source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateObjectsAsync(
        GcsSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        try
        {
            string pageToken = string.Empty;
            int page = 1;
            do
            {
                Uri listUri = CreateListObjectsUri(options, pageToken);
                using HttpResponseMessage response = await SendAsync(options, listUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    WarnUnsuccessfulResponse(options, response, $"skipping GCS bucket {options.Bucket}");
                    return sourceFiles;
                }

                (List<(string Name, long? Size)> objects, string nextPageToken) = await ReadListResponseAsync(options, response.Content, cancellationToken).ConfigureAwait(false);
                await AddObjectFilesAsync(options, objects, sourceFiles, cancellationToken).ConfigureAwait(false);
                pageToken = nextPageToken;
                if (pageToken.Length != 0 && page >= MaxPaginationPages)
                {
                    options.WarningSink?.Invoke($"GCS bucket {options.Bucket} enumeration stopped at the pagination safety limit");
                    break;
                }

                page++;
            }
            while (pageToken.Length != 0 && !IsCancellationRequested(options));
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task AddObjectFilesAsync(
        GcsSourceOptions options,
        List<(string Name, long? Size)> objects,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        for (int i = 0; i < objects.Count; i++)
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            (string name, long? size) = objects[i];
            string displayPath = CreateDisplayPath(options, name);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (size.HasValue && size.Value > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"GCS object byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateObjectUri(options, name);
            byte[]? content = await DownloadObjectAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadObjectAsync(
        GcsSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GCS object {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"GCS object byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GcsSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptRaw ? "application/octet-stream" : "application/json"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Credential);
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(List<(string Name, long? Size)> Objects, string NextPageToken)> ReadListResponseAsync(
        GcsSourceOptions options,
        HttpContent content,
        CancellationToken cancellationToken)
    {
        try
        {
            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                content,
                "GCS source metadata",
                options.WarningSink,
                cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            var objects = new List<(string Name, long? Size)>();
            if (root.TryGetProperty("items", out JsonElement items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in items.EnumerateArray())
                {
                    string name = GetString(item, "name");
                    if (name.Length != 0)
                    {
                        objects.Add((name, GetInt64(item, "size")));
                    }
                }
            }

            return (objects, GetString(root, "nextPageToken"));
        }
        catch (JsonException ex)
        {
            options.WarningSink?.Invoke($"skipping GCS source metadata because JSON parsing failed: {ex.Message}");
            return ([], string.Empty);
        }
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GcsSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
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

                long projectedLength = memory.Length + read;
                if (projectedLength > options.MaxFileBytes)
                {
                    options.WarningSink?.Invoke($"GCS object byte limit skipped {displayPath}");
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

    private static Uri CreateListObjectsUri(GcsSourceOptions options, string pageToken)
    {
        var query = new List<KeyValuePair<string, string>>(5)
        {
            new("maxResults", ListObjectsMaxResults.ToString(CultureInfo.InvariantCulture)),
            new("projection", "noAcl"),
        };
        if (options.Prefix.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("prefix", options.Prefix));
        }

        if (options.UserProject.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("userProject", options.UserProject));
        }

        if (pageToken.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("pageToken", pageToken));
        }

        return CreateUri(options.Endpoint, options.Bucket, objectName: null, query);
    }

    private static Uri CreateObjectUri(GcsSourceOptions options, string objectName)
    {
        var query = new List<KeyValuePair<string, string>>(options.UserProject.Length == 0 ? 1 : 2)
        {
            new("alt", "media"),
        };
        if (options.UserProject.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("userProject", options.UserProject));
        }

        return CreateUri(options.Endpoint, options.Bucket, objectName, query);
    }

    private static Uri CreateUri(
        Uri endpoint,
        string bucket,
        string? objectName,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CreatePath(endpoint.AbsolutePath, bucket, objectName),
            Query = CreateQuery(query),
        };
        return builder.Uri;
    }

    private static string CreatePath(string basePath, string bucket, string? objectName)
    {
        var builder = new StringBuilder();
        string normalizedBasePath = basePath.TrimEnd('/');
        if (normalizedBasePath.Length != 0)
        {
            builder.Append(normalizedBasePath);
        }

        builder.Append("/storage/v1/b/");
        builder.Append(Uri.EscapeDataString(bucket));
        builder.Append("/o");
        if (objectName is not null)
        {
            builder.Append('/');
            builder.Append(Uri.EscapeDataString(objectName));
        }

        return builder.ToString();
    }

    private static string CreateQuery(IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new StringBuilder();
        for (int i = 0; i < query.Count; i++)
        {
            if (builder.Length != 0)
            {
                builder.Append('&');
            }

            builder.Append(Uri.EscapeDataString(query[i].Key));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(query[i].Value));
        }

        return builder.ToString();
    }

    private static string CreateDisplayPath(GcsSourceOptions options, string objectName)
    {
        return string.Concat(
            "gcs/",
            NormalizeRemoteItemPath(options.Bucket),
            "/",
            NormalizeRemoteItemPath(objectName));
    }

    private static string NormalizeRemoteItemPath(string value)
    {
        string[] segments = value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return "_";
        }

        var builder = new StringBuilder();
        for (int i = 0; i < segments.Length; i++)
        {
            if (i != 0)
            {
                builder.Append('/');
            }

            builder.Append(EscapeDisplaySegment(IsUnsafePathSegment(segments[i]) ? "_" : segments[i]));
        }

        return builder.ToString();
    }

    private static string EscapeDisplaySegment(string value)
    {
        return Uri.EscapeDataString(value).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnsafePathSegment(string value)
    {
        return value.Equals(".", StringComparison.Ordinal)
            || value.Equals("..", StringComparison.Ordinal);
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }

    private static long? GetInt64(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out JsonElement property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out long number))
        {
            return number;
        }

        if (property.ValueKind == JsonValueKind.String
            && long.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed))
        {
            return parsed;
        }

        return null;
    }

    private static void WarnUnsuccessfulResponse(
        GcsSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because GCS returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool IsCancellationRequested(GcsSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
