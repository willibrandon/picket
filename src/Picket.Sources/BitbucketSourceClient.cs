using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Bitbucket Cloud repository source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for Bitbucket requests.</param>
public sealed class BitbucketSourceClient(HttpClient httpClient)
{
    private const int DirectoryEntriesPerPage = 100;
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-bitbucket-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Bitbucket repository files selected by the supplied options.
    /// </summary>
    /// <param name="options">The Bitbucket source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateRepositoryFilesAsync(
        BitbucketSourceOptions options,
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
            if (options.PullRequestId != 0)
            {
                (bool shouldScan, BitbucketSourceOptions sourceOptions, string sourceRef) = await ResolvePullRequestSourceAsync(
                    options,
                    cancellationToken).ConfigureAwait(false);
                if (!shouldScan)
                {
                    return sourceFiles;
                }

                await AddRepositoryFilesAsync(sourceOptions, sourceRef, sourceFiles, cancellationToken).ConfigureAwait(false);
                return sourceFiles;
            }

            string gitRef = options.Ref;
            if (gitRef.Length == 0)
            {
                gitRef = await ReadMainBranchAsync(options, cancellationToken).ConfigureAwait(false);
                if (gitRef.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Bitbucket repository {options.Repository} because it does not have a main branch");
                    return sourceFiles;
                }
            }

            await AddRepositoryFilesAsync(options, gitRef, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task<(bool ShouldScan, BitbucketSourceOptions SourceOptions, string SourceRef)> ResolvePullRequestSourceAsync(
        BitbucketSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreatePullRequestUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping Bitbucket pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository}");
            return (false, options, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        string sourceRef = GetNestedString(document.RootElement, "source", "commit", "hash");
        if (sourceRef.Length == 0)
        {
            sourceRef = GetNestedString(document.RootElement, "source", "branch", "name");
        }

        if (sourceRef.Length == 0)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository} because its source head was not returned");
            return (false, options, string.Empty);
        }

        BitbucketSourceOptions sourceOptions = options;
        string sourceRepository = GetNestedString(document.RootElement, "source", "repository", "full_name");
        if (sourceRepository.Length != 0 && !sourceRepository.Equals(options.Repository, StringComparison.Ordinal))
        {
            try
            {
                sourceOptions = options.CreateForRepository(sourceRepository);
            }
            catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository} because its source repository was invalid: {ex.Message}");
                return (false, options, string.Empty);
            }
        }

        return (true, sourceOptions, sourceRef);
    }

    private async Task<string> ReadMainBranchAsync(
        BitbucketSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateRepositoryUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket repository {options.Repository}");
            return string.Empty;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        return GetNestedString(document.RootElement, "mainbranch", "name");
    }

    private async Task AddRepositoryFilesAsync(
        BitbucketSourceOptions options,
        string gitRef,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        var directories = new Queue<string>();
        var visitedDirectories = new HashSet<string>(StringComparer.Ordinal);
        directories.Enqueue(string.Empty);
        visitedDirectories.Add(string.Empty);

        while (directories.Count != 0 && !IsCancellationRequested(options))
        {
            string directoryPath = directories.Dequeue();
            await AddDirectoryFilesAsync(options, gitRef, directoryPath, directories, visitedDirectories, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddDirectoryFilesAsync(
        BitbucketSourceOptions options,
        string gitRef,
        string directoryPath,
        Queue<string> directories,
        HashSet<string> visitedDirectories,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri directoryUri = CreateDirectoryUri(options, gitRef, directoryPath, page);
            using HttpResponseMessage response = await SendAsync(options, directoryUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket directory {CreateDisplayPath(options, directoryPath)}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddDirectoryEntriesAsync(options, gitRef, root, directories, visitedDirectories, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextPage(root, page, entryCount, options.WarningSink, $"Bitbucket directory {CreateDisplayPath(options, directoryPath)} enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddDirectoryEntriesAsync(
        BitbucketSourceOptions options,
        string gitRef,
        JsonElement root,
        Queue<string> directories,
        HashSet<string> visitedDirectories,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("values", out JsonElement values) || values.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int entryCount = 0;
        foreach (JsonElement item in values.EnumerateArray())
        {
            entryCount++;
            if (IsCancellationRequested(options))
            {
                return entryCount;
            }

            if (!TryGetJsonString(item, "path", out string path))
            {
                continue;
            }

            if (IsDirectoryItem(item))
            {
                string normalizedDirectory = NormalizeRepositoryItemPath(path);
                if (visitedDirectories.Add(normalizedDirectory))
                {
                    directories.Enqueue(normalizedDirectory);
                }

                continue;
            }

            if (!IsFileItem(item))
            {
                continue;
            }

            string normalizedPath = NormalizeRepositoryItemPath(path);
            string displayPath = CreateDisplayPath(options, normalizedPath);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (TryGetJsonInt64(item, "size", out long treeSize)
                && treeSize > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateRawFileUri(options, normalizedPath, gitRef);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }

        return entryCount;
    }

    private async Task<byte[]?> DownloadFileAsync(
        BitbucketSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        BitbucketSourceOptions options,
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
                request.Headers.Authorization = CreateAuthorizationHeader(options);
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        BitbucketSourceOptions options,
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
                    options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
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

    private static AuthenticationHeaderValue CreateAuthorizationHeader(BitbucketSourceOptions options)
    {
        return options.CredentialKind switch
        {
            BitbucketCredentialKind.BearerToken => new AuthenticationHeaderValue("Bearer", options.Credential),
            BitbucketCredentialKind.AppPassword => new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(options.Username, ":", options.Credential)))),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };
    }

    private static Uri CreateRepositoryUri(BitbucketSourceOptions options)
    {
        return CreateUri(options.Endpoint, ["repositories", options.Workspace, options.RepositorySlug], itemPath: null, trailingSlash: false, query: []);
    }

    private static Uri CreatePullRequestUri(BitbucketSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "pullrequests", options.PullRequestId.ToString(CultureInfo.InvariantCulture)],
            itemPath: null,
            trailingSlash: false,
            query: []);
    }

    private static Uri CreateDirectoryUri(BitbucketSourceOptions options, string gitRef, string directoryPath, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "src", gitRef],
            directoryPath,
            trailingSlash: true,
            query:
            [
                new KeyValuePair<string, string>("pagelen", DirectoryEntriesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateRawFileUri(BitbucketSourceOptions options, string path, string gitRef)
    {
        return CreateUri(options.Endpoint, ["repositories", options.Workspace, options.RepositorySlug, "src", gitRef], path, trailingSlash: false, query: []);
    }

    private static Uri CreateUri(
        Uri endpoint,
        IReadOnlyList<string> pathSegments,
        string? itemPath,
        bool trailingSlash,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = CombinePath(endpoint.AbsolutePath, pathSegments, itemPath, trailingSlash),
            Query = CreateQuery(query),
        };
        return builder.Uri;
    }

    private static string CombinePath(
        string basePath,
        IReadOnlyList<string> segments,
        string? itemPath,
        bool trailingSlash)
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

        if (trailingSlash && (builder.Length == 0 || builder[^1] != '/'))
        {
            builder.Append('/');
        }

        return builder.Length == 0 ? "/" : builder.ToString();
    }

    private static void AppendEscapedItemPath(StringBuilder builder, string itemPath)
    {
        string[] segments = itemPath.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
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
        BitbucketSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Bitbucket returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool HasNextPage(JsonElement root, int page, int entryCount, Action<string>? warningSink, string target)
    {
        if (entryCount == 0 || !TryGetJsonString(root, "next", out _))
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

    private static bool IsDirectoryItem(JsonElement item)
    {
        return TryGetJsonString(item, "type", out string type)
            && type.Equals("commit_directory", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFileItem(JsonElement item)
    {
        return TryGetJsonString(item, "type", out string type)
            && type.Equals("commit_file", StringComparison.OrdinalIgnoreCase);
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

    private static string GetNestedString(
        JsonElement value,
        string firstPropertyName,
        string secondPropertyName,
        string thirdPropertyName)
    {
        if (!value.TryGetProperty(firstPropertyName, out JsonElement firstProperty)
            || firstProperty.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        if (!firstProperty.TryGetProperty(secondPropertyName, out JsonElement secondProperty)
            || secondProperty.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(secondProperty, thirdPropertyName);
    }

    private static string CreateDisplayPath(BitbucketSourceOptions options, string itemPath)
    {
        string normalizedPath = NormalizeRemoteItemPath(itemPath);
        return normalizedPath.Length == 0
            ? string.Concat("bitbucket/", NormalizeRemoteItemPath(options.Repository))
            : string.Concat(
                "bitbucket/",
                NormalizeRemoteItemPath(options.Repository),
                "/",
                normalizedPath);
    }

    private static string EscapeDisplaySegment(string value)
    {
        return Uri.EscapeDataString(value).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRepositoryItemPath(string value)
    {
        string[] segments = value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (int i = 0; i < segments.Length; i++)
        {
            if (i != 0)
            {
                builder.Append('/');
            }

            builder.Append(IsUnsafePathSegment(segments[i]) ? "_" : segments[i]);
        }

        return builder.ToString();
    }

    private static string NormalizeRemoteItemPath(string value)
    {
        string[] segments = value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return string.Empty;
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

    private static bool IsCancellationRequested(BitbucketSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
