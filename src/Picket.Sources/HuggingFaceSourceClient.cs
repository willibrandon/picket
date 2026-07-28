using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Hugging Face Hub repositories, discussions, pull requests, and storage buckets.
/// </summary>
/// <param name="httpClient">The HTTP client used for Hugging Face requests.</param>
public sealed class HuggingFaceSourceClient(HttpClient httpClient)
{
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-huggingface-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates the Hugging Face resource selected by the supplied options.
    /// </summary>
    /// <param name="options">The Hugging Face source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateAsync(
        HuggingFaceSourceOptions options,
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
            if (options.ResourceKind == HuggingFaceResourceKind.Bucket)
            {
                await AddBucketFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await AddRepositoryFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task AddRepositoryFilesAsync(
        HuggingFaceSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string commit = await ResolveCommitAsync(options, cancellationToken).ConfigureAwait(false);
        if (commit.Length == 0 || IsCancellationRequested(options))
        {
            return;
        }

        await AddRepositoryTreeFilesAsync(options, commit, sourceFiles, cancellationToken).ConfigureAwait(false);
        if (IsCancellationRequested(options))
        {
            return;
        }

        if (options.PullRequestNumber > 0)
        {
            await AddDiscussionFileAsync(
                options,
                commit,
                options.PullRequestNumber,
                isPullRequest: true,
                sourceFiles,
                cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeDiscussions && !IsCancellationRequested(options))
        {
            await AddDiscussionFilesAsync(options, commit, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<string> ResolveCommitAsync(
        HuggingFaceSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateRepositoryInfoUri(options);
        using HttpResponseMessage response = await SendAuthenticatedAsync(
            options,
            uri,
            acceptRaw: false,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, "skipping Hugging Face repository");
            return string.Empty;
        }

        try
        {
            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                response.Content,
                "Hugging Face repository metadata",
                options.WarningSink,
                cancellationToken).ConfigureAwait(false);
            string commit = GetString(document.RootElement, "sha");
            if (commit.Length == 0)
            {
                options.WarningSink?.Invoke("skipping Hugging Face repository because its resolved commit is missing");
            }

            return commit;
        }
        catch (JsonException ex)
        {
            WarnJsonFailure(options, "Hugging Face repository metadata", ex);
            return string.Empty;
        }
    }

    private async Task AddRepositoryTreeFilesAsync(
        HuggingFaceSourceOptions options,
        string commit,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri? pageUri = CreateRepositoryTreeUri(options, commit);
        int page = 1;
        while (pageUri is not null && !IsCancellationRequested(options))
        {
            using HttpResponseMessage response = await SendAuthenticatedAsync(
                options,
                pageUri,
                acceptRaw: false,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, "stopping Hugging Face repository tree enumeration");
                return;
            }

            try
            {
                using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                    response.Content,
                    "Hugging Face repository tree metadata",
                    options.WarningSink,
                    cancellationToken).ConfigureAwait(false);
                await AddRepositoryTreePageAsync(
                    options,
                    commit,
                    document.RootElement,
                    sourceFiles,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (JsonException ex)
            {
                WarnJsonFailure(options, "Hugging Face repository tree metadata", ex);
                return;
            }

            pageUri = GetNextPageUri(options, response, pageUri, page, "Hugging Face repository tree");
            page++;
        }
    }

    private async Task AddRepositoryTreePageAsync(
        HuggingFaceSourceOptions options,
        string commit,
        JsonElement root,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (root.ValueKind != JsonValueKind.Array)
        {
            options.WarningSink?.Invoke("skipping Hugging Face repository tree page because its JSON root is not an array");
            return;
        }

        foreach (JsonElement item in root.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!GetString(item, "type").Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string path = GetString(item, "path");
            if (path.Length == 0)
            {
                continue;
            }

            if (!IsSafeRepositoryFilePath(path))
            {
                options.WarningSink?.Invoke(
                    "skipping Hugging Face repository file because its path contains unsafe segments");
                continue;
            }

            string displayPath = CreateRepositoryDisplayPath(options, commit, path);
            if (IsPathAllowed(options, displayPath))
            {
                continue;
            }

            long? size = GetInt64(item, "size");
            if (size.HasValue && size.Value > options.MaxFileBytes)
            {
                WarnFileByteLimit(options, displayPath);
                continue;
            }

            Uri uri = CreateRepositoryDownloadUri(options, commit, path);
            byte[]? content = await DownloadContentAsync(
                options,
                uri,
                displayPath,
                cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
            }
        }
    }

    private async Task AddDiscussionFilesAsync(
        HuggingFaceSourceOptions options,
        string commit,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 0;
        bool hasNextPage;
        do
        {
            Uri uri = CreateDiscussionListUri(options, page);
            using HttpResponseMessage response = await SendAuthenticatedAsync(
                options,
                uri,
                acceptRaw: false,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, "stopping Hugging Face discussion enumeration");
                return;
            }

            try
            {
                using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                    response.Content,
                    "Hugging Face discussion metadata",
                    options.WarningSink,
                    cancellationToken).ConfigureAwait(false);
                (List<int> discussionNumbers, bool morePages) = ReadDiscussionPage(options, document.RootElement);
                for (int i = 0; i < discussionNumbers.Count; i++)
                {
                    if (IsCancellationRequested(options))
                    {
                        return;
                    }

                    await AddDiscussionFileAsync(
                        options,
                        commit,
                        discussionNumbers[i],
                        isPullRequest: false,
                        sourceFiles,
                        cancellationToken).ConfigureAwait(false);
                }

                hasNextPage = morePages;
            }
            catch (JsonException ex)
            {
                WarnJsonFailure(options, "Hugging Face discussion metadata", ex);
                return;
            }

            page++;
            if (hasNextPage && page >= MaxPaginationPages)
            {
                options.WarningSink?.Invoke("Hugging Face discussion enumeration stopped at the pagination safety limit");
                return;
            }
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddDiscussionFileAsync(
        HuggingFaceSourceOptions options,
        string commit,
        int discussionNumber,
        bool isPullRequest,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateDiscussionDetailsUri(options, discussionNumber);
        using HttpResponseMessage response = await SendAuthenticatedAsync(
            options,
            uri,
            acceptRaw: false,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                string.Concat(
                    "skipping Hugging Face ",
                    isPullRequest ? "pull request " : "discussion ",
                    discussionNumber.ToString(CultureInfo.InvariantCulture)));
            return;
        }

        try
        {
            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                response.Content,
                "Hugging Face discussion details",
                options.WarningSink,
                cancellationToken).ConfigureAwait(false);
            bool responseIsPullRequest = GetBoolean(document.RootElement, "isPullRequest");
            if (responseIsPullRequest != isPullRequest)
            {
                options.WarningSink?.Invoke(string.Concat(
                    "skipping Hugging Face discussion ",
                    discussionNumber.ToString(CultureInfo.InvariantCulture),
                    " because its resource type did not match the requested selector"));
                return;
            }

            byte[] content = CreateDiscussionContent(document.RootElement);
            string displayPath = CreateDiscussionDisplayPath(
                options,
                commit,
                discussionNumber,
                isPullRequest);
            if (content.LongLength > options.MaxFileBytes)
            {
                WarnFileByteLimit(options, displayPath);
                return;
            }

            if (!IsPathAllowed(options, displayPath))
            {
                sourceFiles.Add(CreateSourceFile(options, displayPath, content));
            }
        }
        catch (JsonException ex)
        {
            WarnJsonFailure(options, "Hugging Face discussion details", ex);
        }
    }

    private async Task AddBucketFilesAsync(
        HuggingFaceSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri? pageUri = CreateBucketTreeUri(options);
        int page = 1;
        while (pageUri is not null && !IsCancellationRequested(options))
        {
            using HttpResponseMessage response = await SendAuthenticatedAsync(
                options,
                pageUri,
                acceptRaw: false,
                cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, "stopping Hugging Face bucket enumeration");
                return;
            }

            try
            {
                using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                    response.Content,
                    "Hugging Face bucket tree metadata",
                    options.WarningSink,
                    cancellationToken).ConfigureAwait(false);
                await AddBucketTreePageAsync(
                    options,
                    document.RootElement,
                    sourceFiles,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (JsonException ex)
            {
                WarnJsonFailure(options, "Hugging Face bucket tree metadata", ex);
                return;
            }

            pageUri = GetNextPageUri(options, response, pageUri, page, "Hugging Face bucket");
            page++;
        }
    }

    private async Task AddBucketTreePageAsync(
        HuggingFaceSourceOptions options,
        JsonElement root,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (root.ValueKind != JsonValueKind.Array)
        {
            options.WarningSink?.Invoke("skipping Hugging Face bucket tree page because its JSON root is not an array");
            return;
        }

        foreach (JsonElement item in root.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!GetString(item, "type").Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string path = GetString(item, "path");
            if (path.Length == 0)
            {
                continue;
            }

            string contentIdentity = GetString(item, "xetHash");
            if (contentIdentity.Length == 0)
            {
                contentIdentity = "unversioned";
            }

            string displayPath = CreateBucketDisplayPath(options, contentIdentity, path);
            if (IsPathAllowed(options, displayPath))
            {
                continue;
            }

            long? size = GetInt64(item, "size");
            if (size.HasValue && size.Value > options.MaxFileBytes)
            {
                WarnFileByteLimit(options, displayPath);
                continue;
            }

            Uri uri = CreateBucketDownloadUri(options, path);
            byte[]? content = await DownloadContentAsync(
                options,
                uri,
                displayPath,
                cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
            }
        }
    }

    private async Task<byte[]?> DownloadContentAsync(
        HuggingFaceSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAuthenticatedAsync(
            options,
            uri,
            acceptRaw: true,
            cancellationToken).ConfigureAwait(false);
        if (WasAutoRedirected(response, uri))
        {
            options.WarningSink?.Invoke(
                $"skipping Hugging Face file {displayPath} because the HTTP handler followed a redirect automatically");
            return null;
        }

        if (IsRedirect(response))
        {
            if (response.Headers.Location is null)
            {
                options.WarningSink?.Invoke(
                    $"skipping Hugging Face file {displayPath} because its download redirect had no location");
                return null;
            }

            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedDownloadRedirectUri(options.Endpoint, redirectUri))
            {
                options.WarningSink?.Invoke(
                    $"skipping Hugging Face file {displayPath} because its redirected download URL is not allowed");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(
                redirectUri,
                cancellationToken).ConfigureAwait(false);
            if (WasAutoRedirected(redirectedResponse, redirectUri) || IsRedirect(redirectedResponse))
            {
                options.WarningSink?.Invoke(
                    $"skipping Hugging Face file {displayPath} because its download required more than one redirect");
                return null;
            }

            return await ReadSuccessfulContentAsync(
                options,
                redirectedResponse,
                displayPath,
                cancellationToken).ConfigureAwait(false);
        }

        return await ReadSuccessfulContentAsync(
            options,
            response,
            displayPath,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadSuccessfulContentAsync(
        HuggingFaceSourceOptions options,
        HttpResponseMessage response,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Hugging Face file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength is long contentLength
            && contentLength > options.MaxFileBytes)
        {
            WarnFileByteLimit(options, displayPath);
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

                long projectedLength = memory.Length + read;
                if (projectedLength > options.MaxFileBytes)
                {
                    WarnFileByteLimit(options, displayPath);
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

    private async Task<HttpResponseMessage> SendAuthenticatedAsync(
        HuggingFaceSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () => CreateRequest(uri, acceptRaw, options.Credential),
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendUnauthenticatedRawAsync(
        Uri uri,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () => CreateRequest(uri, acceptRaw: true, credential: null),
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static HttpRequestMessage CreateRequest(Uri uri, bool acceptRaw, string? credential)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
            acceptRaw ? "application/octet-stream" : "application/json"));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
        if (credential is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        }

        return request;
    }

    private static void AddContentOrArchiveEntries(
        HuggingFaceSourceOptions options,
        string displayPath,
        byte[] content,
        List<SourceFile> sourceFiles)
    {
        if (!ArchiveReader.IsArchiveContent(content))
        {
            sourceFiles.Add(CreateSourceFile(options, displayPath, content));
            return;
        }

        if (options.MaxArchiveDepth == 0)
        {
            options.WarningSink?.Invoke(
                $"skipping Hugging Face archive {displayPath} because archive traversal is disabled");
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
            sourceFiles.Add(CreateSourceFile(options, displayPath, content));
            return;
        }

        for (int i = 0; i < entries.Count; i++)
        {
            ArchiveEntry entry = entries[i];
            sourceFiles.Add(CreateSourceFile(options, entry.DisplayPath, entry.Content));
        }
    }

    private static SourceFile CreateSourceFile(
        HuggingFaceSourceOptions options,
        string displayPath,
        byte[] content)
    {
        return new SourceFile(
            s_remoteFullPath,
            displayPath,
            string.Empty,
            content,
            GetProvenanceType(options.ResourceKind));
    }

    private static (List<int> DiscussionNumbers, bool HasNextPage) ReadDiscussionPage(
        HuggingFaceSourceOptions options,
        JsonElement root)
    {
        var discussionNumbers = new List<int>();
        int count = GetInt32(root, "count");
        int start = GetInt32(root, "start");
        if (!root.TryGetProperty("discussions", out JsonElement discussions)
            || discussions.ValueKind != JsonValueKind.Array)
        {
            options.WarningSink?.Invoke(
                "skipping Hugging Face discussion page because its discussions array is missing");
            return (discussionNumbers, false);
        }

        foreach (JsonElement discussion in discussions.EnumerateArray())
        {
            if (GetBoolean(discussion, "isPullRequest"))
            {
                continue;
            }

            int number = GetInt32(discussion, "num");
            if (number > 0)
            {
                discussionNumbers.Add(number);
            }
        }

        return (discussionNumbers, start + discussions.GetArrayLength() < count);
    }

    private static byte[] CreateDiscussionContent(JsonElement root)
    {
        var builder = new StringBuilder();
        string title = GetString(root, "title");
        if (title.Length != 0)
        {
            builder.Append("# ");
            builder.AppendLine(title);
            builder.AppendLine();
        }

        AppendMetadataLine(builder, "Number", GetInt32(root, "num").ToString(CultureInfo.InvariantCulture));
        AppendMetadataLine(builder, "Status", GetString(root, "status"));
        AppendMetadataLine(builder, "Author", GetNestedString(root, "author", "name"));

        if (root.TryGetProperty("events", out JsonElement events)
            && events.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement discussionEvent in events.EnumerateArray())
            {
                if (!GetString(discussionEvent, "type").Equals("comment", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string comment = GetNestedString(discussionEvent, "data", "latest", "raw");
                if (comment.Length == 0)
                {
                    continue;
                }

                builder.AppendLine();
                builder.Append("## Comment by ");
                string author = GetNestedString(discussionEvent, "author", "name");
                builder.AppendLine(author.Length == 0 ? "deleted" : author);
                builder.AppendLine();
                builder.AppendLine(comment);
            }
        }

        string diff = GetString(root, "diff");
        if (diff.Length != 0)
        {
            builder.AppendLine();
            builder.AppendLine("## Diff");
            builder.AppendLine();
            builder.AppendLine("```diff");
            builder.AppendLine(diff);
            builder.AppendLine("```");
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static void AppendMetadataLine(StringBuilder builder, string name, string value)
    {
        if (value.Length == 0)
        {
            return;
        }

        builder.Append(name);
        builder.Append(": ");
        builder.AppendLine(value);
    }

    private static Uri CreateRepositoryInfoUri(HuggingFaceSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "api/",
                GetRepositoryPlural(options.ResourceKind),
                "/",
                EscapePath(options.ResourceId),
                "/revision/",
                Uri.EscapeDataString(options.Revision)));
    }

    private static Uri CreateRepositoryTreeUri(HuggingFaceSourceOptions options, string commit)
    {
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "api/",
                GetRepositoryPlural(options.ResourceKind),
                "/",
                EscapePath(options.ResourceId),
                "/tree/",
                Uri.EscapeDataString(commit),
                "?recursive=true&expand=true"));
    }

    private static Uri CreateRepositoryDownloadUri(
        HuggingFaceSourceOptions options,
        string commit,
        string path)
    {
        string prefix = options.ResourceKind switch
        {
            HuggingFaceResourceKind.Model => string.Empty,
            HuggingFaceResourceKind.Dataset => "datasets/",
            HuggingFaceResourceKind.Space => "spaces/",
            _ => throw new InvalidOperationException("Buckets do not use repository download URLs."),
        };
        return CreateUri(
            options.Endpoint,
            string.Concat(
                prefix,
                EscapePath(options.ResourceId),
                "/resolve/",
                Uri.EscapeDataString(commit),
                "/",
                EscapePath(path)));
    }

    private static Uri CreateDiscussionListUri(HuggingFaceSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "api/",
                GetRepositoryPlural(options.ResourceKind),
                "/",
                EscapePath(options.ResourceId),
                "/discussions?p=",
                page.ToString(CultureInfo.InvariantCulture),
                "&type=discussion&status=all"));
    }

    private static Uri CreateDiscussionDetailsUri(
        HuggingFaceSourceOptions options,
        int discussionNumber)
    {
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "api/",
                GetRepositoryPlural(options.ResourceKind),
                "/",
                EscapePath(options.ResourceId),
                "/discussions/",
                discussionNumber.ToString(CultureInfo.InvariantCulture),
                "?diff=1"));
    }

    private static Uri CreateBucketTreeUri(HuggingFaceSourceOptions options)
    {
        string encodedPrefix = options.BucketPrefix.Length == 0
            ? string.Empty
            : string.Concat("/", Uri.EscapeDataString(options.BucketPrefix));
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "api/buckets/",
                EscapePath(options.ResourceId),
                "/tree",
                encodedPrefix,
                "?recursive=true"));
    }

    private static Uri CreateBucketDownloadUri(HuggingFaceSourceOptions options, string path)
    {
        return CreateUri(
            options.Endpoint,
            string.Concat(
                "buckets/",
                EscapePath(options.ResourceId),
                "/resolve/",
                Uri.EscapeDataString(path)));
    }

    private static Uri CreateUri(Uri endpoint, string relativePath)
    {
        return new Uri(endpoint, relativePath);
    }

    private static Uri? GetNextPageUri(
        HuggingFaceSourceOptions options,
        HttpResponseMessage response,
        Uri currentUri,
        int page,
        string target)
    {
        if (!TryGetNextLink(response, out string nextLink))
        {
            return null;
        }

        if (page >= MaxPaginationPages)
        {
            options.WarningSink?.Invoke($"{target} enumeration stopped at the pagination safety limit");
            return null;
        }

        if (!Uri.TryCreate(currentUri, nextLink, out Uri? nextUri)
            || !IsAllowedMetadataUri(options.Endpoint, nextUri))
        {
            options.WarningSink?.Invoke($"{target} enumeration stopped because its next-page URL is not allowed");
            return null;
        }

        return nextUri;
    }

    private static bool TryGetNextLink(HttpResponseMessage response, out string nextLink)
    {
        nextLink = string.Empty;
        if (!response.Headers.TryGetValues("Link", out IEnumerable<string>? values))
        {
            return false;
        }

        foreach (string value in values)
        {
            string[] links = value.Split(',');
            for (int i = 0; i < links.Length; i++)
            {
                string link = links[i];
                if (!link.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                int start = link.IndexOf('<');
                int end = link.IndexOf('>', start + 1);
                if (start >= 0 && end > start + 1)
                {
                    nextLink = link[(start + 1)..end];
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsAllowedMetadataUri(Uri endpoint, Uri uri)
    {
        return uri.IsAbsoluteUri
            && uri.Scheme.Equals(endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
            && uri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase)
            && uri.Port == endpoint.Port
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath.StartsWith(endpoint.AbsolutePath, StringComparison.Ordinal);
    }

    private static bool IsAllowedDownloadRedirectUri(Uri endpoint, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || uri.Scheme is not "https" and not "http"
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment)
            || endpoint.Scheme == "https" && uri.Scheme != "https")
        {
            return false;
        }

        if (IsSameHostOrSubdomain(endpoint.Host, uri.Host))
        {
            return true;
        }

        return IsPublicHuggingFaceEndpoint(endpoint)
            && (IsSameHostOrSubdomain("huggingface.co", uri.Host)
                || IsSameHostOrSubdomain("hf.co", uri.Host));
    }

    private static bool IsPublicHuggingFaceEndpoint(Uri endpoint)
    {
        return endpoint.Host.Equals("huggingface.co", StringComparison.OrdinalIgnoreCase)
            || endpoint.Host.Equals("hf.co", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSameHostOrSubdomain(string expectedHost, string actualHost)
    {
        return actualHost.Equals(expectedHost, StringComparison.OrdinalIgnoreCase)
            || actualHost.EndsWith(string.Concat(".", expectedHost), StringComparison.OrdinalIgnoreCase);
    }

    private static bool WasAutoRedirected(HttpResponseMessage response, Uri requestedUri)
    {
        Uri? responseUri = response.RequestMessage?.RequestUri;
        return responseUri is not null && responseUri != requestedUri;
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        int statusCode = (int)response.StatusCode;
        return statusCode is 301 or 302 or 303 or 307 or 308;
    }

    private static string CreateRepositoryDisplayPath(
        HuggingFaceSourceOptions options,
        string commit,
        string path)
    {
        return string.Concat(
            "huggingface/",
            GetResourceName(options.ResourceKind),
            "/",
            NormalizeRemoteItemPath(options.ResourceId),
            "/",
            NormalizeRemoteItemPath(commit),
            "/",
            NormalizeRemoteItemPath(path));
    }

    private static string CreateDiscussionDisplayPath(
        HuggingFaceSourceOptions options,
        string commit,
        int discussionNumber,
        bool isPullRequest)
    {
        return string.Concat(
            "huggingface/",
            GetResourceName(options.ResourceKind),
            "/",
            NormalizeRemoteItemPath(options.ResourceId),
            "/",
            NormalizeRemoteItemPath(commit),
            "/",
            isPullRequest ? "pull-requests/" : "discussions/",
            discussionNumber.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateBucketDisplayPath(
        HuggingFaceSourceOptions options,
        string contentIdentity,
        string path)
    {
        return string.Concat(
            "huggingface/bucket/",
            NormalizeRemoteItemPath(options.ResourceId),
            "/",
            NormalizeRemoteItemPath(contentIdentity),
            "/",
            NormalizeRemoteItemPath(path));
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

            string segment = IsUnsafePathSegment(segments[i]) ? "_" : segments[i];
            builder.Append(Uri.EscapeDataString(segment).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase));
        }

        return builder.ToString();
    }

    private static bool IsUnsafePathSegment(string value)
    {
        return value.Equals(".", StringComparison.Ordinal)
            || value.Equals("..", StringComparison.Ordinal);
    }

    private static bool IsSafeRepositoryFilePath(string value)
    {
        return !value.StartsWith('/')
            && !value.Contains('\\')
            && value.Split('/').All(static segment => segment.Length != 0 && !IsUnsafePathSegment(segment));
    }

    private static string EscapePath(string value)
    {
        return string.Join('/', value.Split('/').Select(Uri.EscapeDataString));
    }

    private static string GetRepositoryPlural(HuggingFaceResourceKind resourceKind)
    {
        return resourceKind switch
        {
            HuggingFaceResourceKind.Model => "models",
            HuggingFaceResourceKind.Dataset => "datasets",
            HuggingFaceResourceKind.Space => "spaces",
            _ => throw new InvalidOperationException("Buckets do not use repository APIs."),
        };
    }

    private static string GetResourceName(HuggingFaceResourceKind resourceKind)
    {
        return resourceKind switch
        {
            HuggingFaceResourceKind.Model => "model",
            HuggingFaceResourceKind.Dataset => "dataset",
            HuggingFaceResourceKind.Space => "space",
            HuggingFaceResourceKind.Bucket => "bucket",
            _ => throw new ArgumentOutOfRangeException(nameof(resourceKind), resourceKind, "Unknown resource kind."),
        };
    }

    private static string GetProvenanceType(HuggingFaceResourceKind resourceKind)
    {
        return string.Concat("huggingface-", GetResourceName(resourceKind));
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }

    private static string GetNestedString(
        JsonElement element,
        string firstPropertyName,
        string secondPropertyName)
    {
        return element.TryGetProperty(firstPropertyName, out JsonElement firstProperty)
            && firstProperty.ValueKind == JsonValueKind.Object
            ? GetString(firstProperty, secondPropertyName)
            : string.Empty;
    }

    private static string GetNestedString(
        JsonElement element,
        string firstPropertyName,
        string secondPropertyName,
        string thirdPropertyName)
    {
        if (!element.TryGetProperty(firstPropertyName, out JsonElement firstProperty)
            || firstProperty.ValueKind != JsonValueKind.Object
            || !firstProperty.TryGetProperty(secondPropertyName, out JsonElement secondProperty)
            || secondProperty.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(secondProperty, thirdPropertyName);
    }

    private static int GetInt32(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt32(out int value)
            ? value
            : 0;
    }

    private static long? GetInt64(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out long value)
            ? value
            : null;
    }

    private static bool GetBoolean(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind is JsonValueKind.True or JsonValueKind.False
            && property.GetBoolean();
    }

    private static bool IsPathAllowed(HuggingFaceSourceOptions options, string displayPath)
    {
        return options.IsPathAllowed is not null && options.IsPathAllowed(displayPath);
    }

    private static bool IsCancellationRequested(HuggingFaceSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static void WarnFileByteLimit(HuggingFaceSourceOptions options, string displayPath)
    {
        options.WarningSink?.Invoke($"Hugging Face file byte limit skipped {displayPath}");
    }

    private static void WarnJsonFailure(
        HuggingFaceSourceOptions options,
        string target,
        JsonException exception)
    {
        options.WarningSink?.Invoke($"skipping {target} because JSON parsing failed: {exception.Message}");
    }

    private static void WarnUnsuccessfulResponse(
        HuggingFaceSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Hugging Face returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }
}
