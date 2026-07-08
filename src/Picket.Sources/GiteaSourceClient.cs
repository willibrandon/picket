using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Gitea repository source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for Gitea requests.</param>
public sealed class GiteaSourceClient(HttpClient httpClient)
{
    private const int MaxPaginationPages = 1000;
    private const int TreeEntriesPerPage = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-gitea-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Gitea repository files selected by the supplied options.
    /// </summary>
    /// <param name="options">The Gitea source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateRepositoryFilesAsync(
        GiteaSourceOptions options,
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
            string gitRef = options.Ref;
            if (gitRef.Length == 0)
            {
                gitRef = await ReadDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
                if (gitRef.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Gitea repository {options.Repository} because it does not have a default branch");
                    return sourceFiles;
                }
            }

            string treeRef = await ResolveTreeRefAsync(options, gitRef, cancellationToken).ConfigureAwait(false);
            await AddRepositoryFilesAsync(options, gitRef, treeRef, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task<string> ReadDefaultBranchAsync(
        GiteaSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateRepositoryUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Gitea repository {options.Repository}");
            return string.Empty;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        JsonElement root = document.RootElement;
        if (TryGetJsonBoolean(root, "empty", out bool empty) && empty)
        {
            return string.Empty;
        }

        return GetString(root, "default_branch");
    }

    private async Task<string> ResolveTreeRefAsync(
        GiteaSourceOptions options,
        string gitRef,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateBranchUri(options, gitRef);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return gitRef;
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"using unresolved Gitea ref {gitRef} for repository {options.Repository}");
            return gitRef;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        string commitId = GetNestedString(document.RootElement, "commit", "id");
        return commitId.Length == 0 ? gitRef : commitId;
    }

    private async Task AddRepositoryFilesAsync(
        GiteaSourceOptions options,
        string gitRef,
        string treeRef,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri treeUri = CreateTreeUri(options, treeRef, page);
            using HttpResponseMessage response = await SendAsync(options, treeUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Gitea repository tree {options.Repository}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddTreeEntriesAsync(options, gitRef, root, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextTreePage(root, page, entryCount, options.WarningSink, $"Gitea repository {options.Repository} tree enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddTreeEntriesAsync(
        GiteaSourceOptions options,
        string gitRef,
        JsonElement root,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("tree", out JsonElement tree) || tree.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int entryCount = 0;
        foreach (JsonElement item in tree.EnumerateArray())
        {
            entryCount++;
            if (IsCancellationRequested(options))
            {
                return entryCount;
            }

            if (!IsBlobItem(item) || !TryGetJsonString(item, "path", out string path))
            {
                continue;
            }

            string displayPath = CreateDisplayPath(options, path);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (TryGetJsonInt64(item, "size", out long treeSize)
                && treeSize > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateRawFileUri(options, path, gitRef);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }

        return entryCount;
    }

    private async Task<byte[]?> DownloadFileAsync(
        GiteaSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Gitea file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GiteaSourceOptions options,
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
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
                request.Headers.TryAddWithoutValidation("Authorization", string.Concat("token ", options.Credential));
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GiteaSourceOptions options,
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
                    options.WarningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
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

    private static Uri CreateRepositoryUri(GiteaSourceOptions options)
    {
        return CreateUri(options.Endpoint, ["repos", options.Owner, options.Name], []);
    }

    private static Uri CreateBranchUri(GiteaSourceOptions options, string gitRef)
    {
        return CreateUri(options.Endpoint, ["repos", options.Owner, options.Name, "branches", gitRef], []);
    }

    private static Uri CreateTreeUri(GiteaSourceOptions options, string treeRef, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "git", "trees", treeRef],
            [
                new KeyValuePair<string, string>("recursive", "true"),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("per_page", TreeEntriesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateRawFileUri(GiteaSourceOptions options, string path, string gitRef)
    {
        var builder = new UriBuilder(options.Endpoint)
        {
            Path = CombinePath(options.Endpoint.AbsolutePath, ["repos", options.Owner, options.Name, "raw"], path),
            Query = CreateQuery([new KeyValuePair<string, string>("ref", gitRef)]),
        };
        return builder.Uri;
    }

    private static Uri CreateUri(
        Uri endpoint,
        IReadOnlyList<string> pathSegments,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CombinePath(endpoint.AbsolutePath, pathSegments, itemPath: null),
            Query = CreateQuery(query),
        };
        return builder.Uri;
    }

    private static string CombinePath(string basePath, IReadOnlyList<string> segments, string? itemPath)
    {
        var builder = new StringBuilder();
        string normalizedBasePath = basePath.TrimEnd('/');
        if (normalizedBasePath.Length != 0)
        {
            builder.Append(normalizedBasePath);
        }

        for (int i = 0; i < segments.Count; i++)
        {
            builder.Append('/');
            builder.Append(Uri.EscapeDataString(segments[i]));
        }

        if (itemPath is not null)
        {
            AppendEscapedItemPath(builder, itemPath);
        }

        return builder.Length == 0 ? "/" : builder.ToString();
    }

    private static void AppendEscapedItemPath(StringBuilder builder, string itemPath)
    {
        string[] segments = itemPath.Replace('\\', '/').Split('/');
        for (int i = 0; i < segments.Length; i++)
        {
            builder.Append('/');
            builder.Append(Uri.EscapeDataString(segments[i]));
        }
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

    private static void WarnUnsuccessfulResponse(
        GiteaSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Gitea returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool HasNextTreePage(JsonElement root, int page, int entryCount, Action<string>? warningSink, string target)
    {
        if (entryCount == 0 || !TryGetJsonBoolean(root, "truncated", out bool truncated) || !truncated)
        {
            return false;
        }

        if (TryGetJsonInt64(root, "total_count", out long totalCount)
            && page * TreeEntriesPerPage >= totalCount)
        {
            return false;
        }

        if (page >= MaxPaginationPages)
        {
            warningSink?.Invoke($"{target} stopped at the pagination safety limit");
            return false;
        }

        return true;
    }

    private static bool IsBlobItem(JsonElement item)
    {
        return TryGetJsonString(item, "type", out string type)
            && (type.Equals("blob", StringComparison.OrdinalIgnoreCase)
                || type.Equals("file", StringComparison.OrdinalIgnoreCase));
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

    private static bool TryGetJsonBoolean(JsonElement value, string propertyName, out bool propertyValue)
    {
        propertyValue = false;
        if (!value.TryGetProperty(propertyName, out JsonElement property)
            || property.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            return false;
        }

        propertyValue = property.GetBoolean();
        return true;
    }

    private static bool TryGetJsonInt64(JsonElement value, string propertyName, out long propertyValue)
    {
        propertyValue = 0;
        if (!value.TryGetProperty(propertyName, out JsonElement property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Number)
        {
            return property.TryGetInt64(out propertyValue);
        }

        return property.ValueKind == JsonValueKind.String
            && long.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out propertyValue);
    }

    private static string GetString(JsonElement value, string propertyName)
    {
        return TryGetJsonString(value, propertyName, out string propertyValue) ? propertyValue : string.Empty;
    }

    private static string GetNestedString(JsonElement value, string firstPropertyName, string secondPropertyName)
    {
        if (!value.TryGetProperty(firstPropertyName, out JsonElement firstProperty)
            || firstProperty.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(firstProperty, secondPropertyName);
    }

    private static string CreateDisplayPath(GiteaSourceOptions options, string itemPath)
    {
        return string.Concat(
            "gitea/",
            NormalizeRemoteItemPath(options.Repository),
            "/",
            NormalizeRemoteItemPath(itemPath));
    }

    private static string EscapeDisplaySegment(string value)
    {
        return Uri.EscapeDataString(value).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase);
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

    private static bool IsUnsafePathSegment(string value)
    {
        return value.Equals(".", StringComparison.Ordinal)
            || value.Equals("..", StringComparison.Ordinal);
    }

    private static bool IsCancellationRequested(GiteaSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
