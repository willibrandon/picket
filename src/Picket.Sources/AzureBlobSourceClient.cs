using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Xml;

namespace Picket.Sources;

/// <summary>
/// Enumerates Azure Blob Storage objects through the Blob service REST API.
/// </summary>
/// <param name="httpClient">The HTTP client used for Blob service requests.</param>
public sealed class AzureBlobSourceClient(HttpClient httpClient)
{
    private const int ListBlobsMaxResults = 5000;
    private const int MaxPaginationPages = 1000;
    private const string StorageServiceVersion = "2026-04-06";
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-azure-blob-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Azure Blob Storage objects selected by the supplied options.
    /// </summary>
    /// <param name="options">The Azure Blob source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateBlobsAsync(
        AzureBlobSourceOptions options,
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
            string marker = string.Empty;
            int page = 1;
            do
            {
                Uri listUri = CreateListBlobsUri(options, marker);
                using HttpResponseMessage response = await SendAsync(options, listUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    WarnUnsuccessfulResponse(options, response, $"skipping Azure Blob container {options.Container}");
                    return sourceFiles;
                }

                (List<(string Name, long? ContentLength)> blobs, string nextMarker) = await ReadListResponseAsync(options, response.Content, cancellationToken).ConfigureAwait(false);
                await AddBlobFilesAsync(options, blobs, sourceFiles, cancellationToken).ConfigureAwait(false);
                marker = nextMarker;
                if (marker.Length != 0 && page >= MaxPaginationPages)
                {
                    options.WarningSink?.Invoke($"Azure Blob container {options.Container} enumeration stopped at the pagination safety limit");
                    break;
                }

                page++;
            }
            while (marker.Length != 0 && !IsCancellationRequested(options));
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task AddBlobFilesAsync(
        AzureBlobSourceOptions options,
        List<(string Name, long? ContentLength)> blobs,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        for (int i = 0; i < blobs.Count; i++)
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            (string name, long? contentLength) = blobs[i];
            string displayPath = CreateDisplayPath(options, name);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (contentLength.HasValue && contentLength.Value > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Azure Blob byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateBlobUri(options, name);
            byte[]? content = await DownloadBlobAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadBlobAsync(
        AzureBlobSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure Blob {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Azure Blob byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        AzureBlobSourceOptions options,
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
                request.Headers.Add("x-ms-version", StorageServiceVersion);
                if (options.CredentialKind == AzureBlobCredentialKind.BearerToken)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Credential);
                }

                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(List<(string Name, long? ContentLength)> Blobs, string NextMarker)> ReadListResponseAsync(
        AzureBlobSourceOptions options,
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long contentLength && contentLength > RemoteJsonDocumentReader.DefaultMaxMetadataBytes)
        {
            ThrowMetadataTooLarge(options, contentLength);
        }

        using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var cappedStream = new CappedReadStream(stream, RemoteJsonDocumentReader.DefaultMaxMetadataBytes, "Azure Blob source metadata");
        var settings = new XmlReaderSettings
        {
            Async = true,
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };
        using XmlReader reader = XmlReader.Create(cappedStream, settings);
        var blobs = new List<(string Name, long? ContentLength)>();
        string currentName = string.Empty;
        long? currentContentLength = null;
        string nextMarker = string.Empty;
        bool inBlob = false;
        try
        {
            while (await reader.ReadAsync().ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.LocalName.Equals("Blob", StringComparison.Ordinal))
                    {
                        inBlob = true;
                        currentName = string.Empty;
                        currentContentLength = null;
                        continue;
                    }

                    if (reader.LocalName.Equals("Name", StringComparison.Ordinal) && inBlob)
                    {
                        currentName = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        continue;
                    }

                    if (reader.LocalName.Equals("Content-Length", StringComparison.Ordinal) && inBlob)
                    {
                        string length = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        if (long.TryParse(length, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsedLength))
                        {
                            currentContentLength = parsedLength;
                        }

                        continue;
                    }

                    if (reader.LocalName.Equals("NextMarker", StringComparison.Ordinal))
                    {
                        nextMarker = await reader.ReadElementContentAsStringAsync().ConfigureAwait(false);
                        continue;
                    }
                }

                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName.Equals("Blob", StringComparison.Ordinal))
                {
                    if (currentName.Length != 0)
                    {
                        blobs.Add((currentName, currentContentLength));
                    }

                    inBlob = false;
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
            options.WarningSink?.Invoke($"skipping Azure Blob source metadata because XML parsing failed: {ex.Message}");
            return ([], string.Empty);
        }

        return (blobs, nextMarker);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        AzureBlobSourceOptions options,
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
                    options.WarningSink?.Invoke($"Azure Blob byte limit skipped {displayPath}");
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

    private static Uri CreateListBlobsUri(AzureBlobSourceOptions options, string marker)
    {
        var query = new List<KeyValuePair<string, string>>(5)
        {
            new("restype", "container"),
            new("comp", "list"),
            new("maxresults", ListBlobsMaxResults.ToString(CultureInfo.InvariantCulture)),
        };
        if (options.Prefix.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("prefix", options.Prefix));
        }

        if (marker.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("marker", marker));
        }

        return CreateUri(options.Endpoint, options.Container, blobName: null, query, options.SasQuery);
    }

    private static Uri CreateBlobUri(AzureBlobSourceOptions options, string blobName)
    {
        return CreateUri(options.Endpoint, options.Container, blobName, [], options.SasQuery);
    }

    private static Uri CreateUri(
        Uri endpoint,
        string container,
        string? blobName,
        IReadOnlyList<KeyValuePair<string, string>> query,
        string sasQuery)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CreatePath(endpoint.AbsolutePath, container, blobName),
            Query = CreateQuery(query, sasQuery),
        };
        return builder.Uri;
    }

    private static string CreatePath(string basePath, string container, string? blobName)
    {
        var builder = new StringBuilder();
        string normalizedBasePath = basePath.TrimEnd('/');
        if (normalizedBasePath.Length != 0)
        {
            builder.Append(normalizedBasePath);
        }

        builder.Append('/');
        builder.Append(Uri.EscapeDataString(container));
        if (blobName is not null)
        {
            builder.Append('/');
            AppendEscapedBlobName(builder, blobName);
        }

        return builder.ToString();
    }

    private static void AppendEscapedBlobName(StringBuilder builder, string blobName)
    {
        string[] segments = blobName.Replace('\\', '/').Split('/');
        for (int i = 0; i < segments.Length; i++)
        {
            if (i != 0)
            {
                builder.Append('/');
            }

            builder.Append(Uri.EscapeDataString(segments[i]));
        }
    }

    private static string CreateQuery(IReadOnlyList<KeyValuePair<string, string>> query, string sasQuery)
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

        if (sasQuery.Length != 0)
        {
            if (builder.Length != 0)
            {
                builder.Append('&');
            }

            builder.Append(sasQuery);
        }

        return builder.ToString();
    }

    private static string CreateDisplayPath(AzureBlobSourceOptions options, string blobName)
    {
        return string.Concat(
            "azure-blob/",
            NormalizeRemoteItemPath(options.Endpoint.DnsSafeHost),
            "/",
            NormalizeRemoteItemPath(options.Container),
            "/",
            NormalizeRemoteItemPath(blobName));
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
        AzureBlobSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Azure Blob Storage returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static void ThrowMetadataTooLarge(AzureBlobSourceOptions options, long contentLength)
    {
        string message = string.Create(
            CultureInfo.InvariantCulture,
            $"skipping Azure Blob source metadata because remote metadata response reported {contentLength} bytes, exceeding the {RemoteJsonDocumentReader.DefaultMaxMetadataBytes} byte metadata cap");
        options.WarningSink?.Invoke(message);
        throw new RemoteMetadataTooLargeException(message);
    }

    private static bool IsCancellationRequested(AzureBlobSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
