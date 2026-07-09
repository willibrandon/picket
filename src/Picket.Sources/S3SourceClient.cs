using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Xml;

namespace Picket.Sources;

/// <summary>
/// Enumerates Amazon S3 objects through the S3 REST API.
/// </summary>
/// <param name="httpClient">The HTTP client used for S3 requests.</param>
public sealed class S3SourceClient(HttpClient httpClient)
{
    private const int ListObjectsMaxKeys = 1000;
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-s3-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Amazon S3 objects selected by the supplied options.
    /// </summary>
    /// <param name="options">The S3 source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateObjectsAsync(
        S3SourceOptions options,
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
            string continuationToken = string.Empty;
            int page = 1;
            do
            {
                Uri listUri = CreateListObjectsUri(options, continuationToken);
                using HttpResponseMessage response = await SendAsync(options, listUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    WarnUnsuccessfulResponse(options, response, $"skipping S3 bucket {options.Bucket}");
                    return sourceFiles;
                }

                (List<(string Key, long? Size)> objects, string nextContinuationToken) = await ReadListResponseAsync(options, response.Content, cancellationToken).ConfigureAwait(false);
                await AddObjectFilesAsync(options, objects, sourceFiles, cancellationToken).ConfigureAwait(false);
                continuationToken = nextContinuationToken;
                if (continuationToken.Length != 0 && page >= MaxPaginationPages)
                {
                    options.WarningSink?.Invoke($"S3 bucket {options.Bucket} enumeration stopped at the pagination safety limit");
                    break;
                }

                page++;
            }
            while (continuationToken.Length != 0 && !IsCancellationRequested(options));
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task AddObjectFilesAsync(
        S3SourceOptions options,
        List<(string Key, long? Size)> objects,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        for (int i = 0; i < objects.Count; i++)
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            (string key, long? size) = objects[i];
            string displayPath = CreateDisplayPath(options, key);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (size.HasValue && size.Value > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"S3 object byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateObjectUri(options, key);
            byte[]? content = await DownloadObjectAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadObjectAsync(
        S3SourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping S3 object {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"S3 object byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        S3SourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptRaw ? "application/octet-stream" : "application/xml"));
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
                S3RequestSigner.Sign(request, options, DateTimeOffset.UtcNow);
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(List<(string Key, long? Size)> Objects, string NextContinuationToken)> ReadListResponseAsync(
        S3SourceOptions options,
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long contentLength && contentLength > RemoteJsonDocumentReader.DefaultMaxMetadataBytes)
        {
            ThrowMetadataTooLarge(options, contentLength);
        }

        using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var cappedStream = new CappedReadStream(stream, RemoteJsonDocumentReader.DefaultMaxMetadataBytes, "S3 source metadata");
        var settings = new XmlReaderSettings
        {
            Async = true,
            DtdProcessing = DtdProcessing.Prohibit,
            MaxCharactersInDocument = RemoteJsonDocumentReader.DefaultMaxMetadataBytes,
            XmlResolver = null,
        };
        using XmlReader reader = XmlReader.Create(cappedStream, settings);
        var objects = new List<(string Key, long? Size)>();
        string currentKey = string.Empty;
        long? currentSize = null;
        string nextContinuationToken = string.Empty;
        bool inContents = false;
        try
        {
            while (await reader.ReadAsync().ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.LocalName.Equals("Contents", StringComparison.Ordinal))
                    {
                        inContents = true;
                        currentKey = string.Empty;
                        currentSize = null;
                        continue;
                    }

                    if (reader.LocalName.Equals("Key", StringComparison.Ordinal) && inContents)
                    {
                        currentKey = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        continue;
                    }

                    if (reader.LocalName.Equals("Size", StringComparison.Ordinal) && inContents)
                    {
                        string size = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        if (long.TryParse(size, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsedSize))
                        {
                            currentSize = parsedSize;
                        }

                        continue;
                    }

                    if (reader.LocalName.Equals("NextContinuationToken", StringComparison.Ordinal))
                    {
                        nextContinuationToken = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        continue;
                    }
                }

                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName.Equals("Contents", StringComparison.Ordinal))
                {
                    if (currentKey.Length != 0)
                    {
                        objects.Add((currentKey, currentSize));
                    }

                    inContents = false;
                }
            }
        }
        catch (RemoteMetadataTooLargeException ex)
        {
            options.WarningSink?.Invoke(ex.Message);
            throw;
        }
        catch (XmlException ex)
        {
            options.WarningSink?.Invoke($"skipping S3 source metadata because XML parsing failed: {ex.Message}");
            return ([], string.Empty);
        }

        return (objects, nextContinuationToken);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        S3SourceOptions options,
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
                    options.WarningSink?.Invoke($"S3 object byte limit skipped {displayPath}");
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

    private static Uri CreateListObjectsUri(S3SourceOptions options, string continuationToken)
    {
        var query = new List<KeyValuePair<string, string>>(4)
        {
            new("list-type", "2"),
            new("max-keys", ListObjectsMaxKeys.ToString(CultureInfo.InvariantCulture)),
        };
        if (options.Prefix.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("prefix", options.Prefix));
        }

        if (continuationToken.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("continuation-token", continuationToken));
        }

        return CreateUri(options.Endpoint, options.Bucket, objectKey: null, query);
    }

    private static Uri CreateObjectUri(S3SourceOptions options, string objectKey)
    {
        return CreateUri(options.Endpoint, options.Bucket, objectKey, []);
    }

    private static Uri CreateUri(
        Uri endpoint,
        string bucket,
        string? objectKey,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CreatePath(endpoint.AbsolutePath, bucket, objectKey),
            Query = CreateQuery(query),
        };
        return builder.Uri;
    }

    private static string CreatePath(string basePath, string bucket, string? objectKey)
    {
        var builder = new StringBuilder();
        string normalizedBasePath = basePath.TrimEnd('/');
        if (normalizedBasePath.Length != 0)
        {
            builder.Append(normalizedBasePath);
        }

        builder.Append('/');
        builder.Append(Uri.EscapeDataString(bucket));
        if (objectKey is not null)
        {
            builder.Append('/');
            AppendEscapedObjectKey(builder, objectKey);
        }

        return builder.ToString();
    }

    private static void AppendEscapedObjectKey(StringBuilder builder, string objectKey)
    {
        string[] segments = objectKey.Replace('\\', '/').Split('/');
        for (int i = 0; i < segments.Length; i++)
        {
            if (i != 0)
            {
                builder.Append('/');
            }

            builder.Append(Uri.EscapeDataString(segments[i]));
        }
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

    private static string CreateDisplayPath(S3SourceOptions options, string objectKey)
    {
        return string.Concat(
            "s3/",
            NormalizeRemoteItemPath(options.Bucket),
            "/",
            NormalizeRemoteItemPath(objectKey));
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

    private static void WarnUnsuccessfulResponse(
        S3SourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because S3 returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static void ThrowMetadataTooLarge(S3SourceOptions options, long contentLength)
    {
        string message = string.Create(
            CultureInfo.InvariantCulture,
            $"skipping S3 source metadata because remote metadata response reported {contentLength} bytes, exceeding the {RemoteJsonDocumentReader.DefaultMaxMetadataBytes} byte metadata cap");
        options.WarningSink?.Invoke(message);
        throw new RemoteMetadataTooLargeException(message);
    }

    private static bool IsCancellationRequested(S3SourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
