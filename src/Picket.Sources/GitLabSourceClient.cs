using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates GitLab repository source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for GitLab requests.</param>
public sealed class GitLabSourceClient(HttpClient httpClient)
{
    private const int GroupProjectsPerPage = 100;
    private const int SnippetsPerPage = 100;
    private const int TreeEntriesPerPage = 100;
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-gitlab-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates GitLab repository files selected by the supplied options.
    /// </summary>
    /// <param name="options">The GitLab source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateRepositoryFilesAsync(
        GitLabSourceOptions options,
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
            if (options.MergeRequestIid != 0)
            {
                (bool shouldScan, GitLabSourceOptions sourceOptions, string sourceRef) = await ResolveMergeRequestSourceAsync(
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
            bool hasRepositoryFiles = true;
            if (gitRef.Length == 0)
            {
                gitRef = await ReadDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
                if (gitRef.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping GitLab project {options.Project} because it does not have a default branch");
                    hasRepositoryFiles = false;
                }
            }

            if (hasRepositoryFiles)
            {
                await AddRepositoryFilesAsync(options, gitRef, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeSnippets && !IsCancellationRequested(options))
            {
                await AddProjectSnippetFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates GitLab repository files for projects selected by the supplied group options.
    /// </summary>
    /// <param name="options">The GitLab group source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateGroupRepositoryFilesAsync(
        GitLabGroupSourceOptions options,
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
            int page = 1;
            bool hasNextPage;
            do
            {
                Uri groupProjectsUri = CreateGroupProjectsUri(options, page);
                using HttpResponseMessage groupProjectsResponse = await SendAsync(options, groupProjectsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
                if (!groupProjectsResponse.IsSuccessStatusCode)
                {
                    options.WarningSink?.Invoke($"skipping GitLab group {options.Group} projects because GitLab returned {((int)groupProjectsResponse.StatusCode).ToString(CultureInfo.InvariantCulture)} {groupProjectsResponse.StatusCode}");
                    return sourceFiles;
                }

                await AddGroupProjectFilesAsync(options, groupProjectsResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
                hasNextPage = HasNextPage(groupProjectsResponse, page, options.WarningSink, $"GitLab group {options.Group} project enumeration");
                page++;
            }
            while (hasNextPage && !IsCancellationRequested(options));
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task<(bool ShouldScan, GitLabSourceOptions SourceOptions, string SourceRef)> ResolveMergeRequestSourceAsync(
        GitLabSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateMergeRequestUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "GitLab source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        JsonElement root = document.RootElement;
        string sourceRef = GetNestedString(root, "diff_refs", "head_sha");
        if (sourceRef.Length == 0)
        {
            sourceRef = GetString(root, "sha");
        }

        if (sourceRef.Length == 0)
        {
            sourceRef = GetString(root, "source_branch");
        }

        if (sourceRef.Length == 0)
        {
            options.WarningSink?.Invoke($"skipping GitLab merge request {options.MergeRequestIid.ToString(CultureInfo.InvariantCulture)} in project {options.Project} because its source ref was not returned");
            return (false, options, string.Empty);
        }

        string sourceProject = options.Project;
        if (TryGetJsonInt64(root, "source_project_id", out long sourceProjectId)
            && sourceProjectId > 0
            && (!TryGetJsonInt64(root, "target_project_id", out long targetProjectId) || sourceProjectId != targetProjectId))
        {
            sourceProject = sourceProjectId.ToString(CultureInfo.InvariantCulture);
        }

        var sourceOptions = new GitLabSourceOptions(
            options.Endpoint,
            sourceProject,
            options.Credential,
            sourceRef,
            maxFileBytes: options.MaxFileBytes,
            isPathAllowed: options.IsPathAllowed,
            warningSink: options.WarningSink,
            isCancellationRequested: options.IsCancellationRequested);
        return (true, sourceOptions, sourceRef);
    }

    private async Task AddGroupProjectFilesAsync(
        GitLabGroupSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "GitLab source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            string project = GetGroupProjectIdentifier(item);
            if (project.Length == 0)
            {
                continue;
            }

            string gitRef = options.Ref.Length == 0 ? GetString(item, "default_branch") : options.Ref;
            var projectOptions = new GitLabSourceOptions(
                options.Endpoint,
                project,
                options.Credential,
                gitRef,
                includeSnippets: options.IncludeSnippets,
                maxFileBytes: options.MaxFileBytes,
                isPathAllowed: options.IsPathAllowed,
                warningSink: options.WarningSink,
                isCancellationRequested: options.IsCancellationRequested);
            List<SourceFile> projectFiles = await EnumerateRepositoryFilesAsync(projectOptions, cancellationToken).ConfigureAwait(false);
            sourceFiles.AddRange(projectFiles);
        }
    }

    private async Task AddProjectSnippetFilesAsync(
        GitLabSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri snippetsUri = CreateSnippetsUri(options, page);
            using HttpResponseMessage snippetsResponse = await SendAsync(options, snippetsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!snippetsResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, snippetsResponse, $"skipping GitLab project {options.Project} snippets");
                return;
            }

            await AddSnippetFilesAsync(options, snippetsResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(snippetsResponse, page, options.WarningSink, $"GitLab project {options.Project} snippet enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddSnippetFilesAsync(
        GitLabSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "GitLab source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonInt64(item, "id", out long snippetId))
            {
                continue;
            }

            string displayPath = CreateSnippetDisplayPath(options, snippetId, GetString(item, "file_name"));
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            Uri rawUri = CreateSnippetRawUri(options, snippetId);
            byte[]? content = await DownloadFileAsync(options, rawUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<string> ReadDefaultBranchAsync(
        GitLabSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateProjectUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "GitLab source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        return GetString(document.RootElement, "default_branch");
    }

    private async Task AddRepositoryFilesAsync(
        GitLabSourceOptions options,
        string gitRef,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri treeUri = CreateTreeUri(options, gitRef, page);
            using HttpResponseMessage treeResponse = await SendAsync(options, treeUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!treeResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, treeResponse, $"skipping GitLab project {options.Project}");
                return;
            }

            await AddTreeFilesAsync(options, gitRef, treeResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(treeResponse, page, options.WarningSink, $"GitLab project {options.Project} tree enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddTreeFilesAsync(
        GitLabSourceOptions options,
        string gitRef,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "GitLab source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
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
                options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateRawFileUri(options, path, gitRef);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadFileAsync(
        GitLabSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitLab file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GitLabSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(options.Credential, uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GitLabGroupSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(options.Credential, uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        string credential,
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
                request.Headers.Add("PRIVATE-TOKEN", credential);
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GitLabSourceOptions options,
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
                    options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
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

    private static Uri CreateGroupProjectsUri(GitLabGroupSourceOptions options, int page)
    {
        var query = new List<KeyValuePair<string, string>>(3)
        {
            new("per_page", GroupProjectsPerPage.ToString(CultureInfo.InvariantCulture)),
            new("page", page.ToString(CultureInfo.InvariantCulture)),
        };
        if (options.IncludeSubgroups)
        {
            query.Add(new KeyValuePair<string, string>("include_subgroups", "true"));
        }

        return CreateUri(options.Endpoint, ["groups", options.Group, "projects"], query);
    }

    private static Uri CreateProjectUri(GitLabSourceOptions options)
    {
        return CreateUri(options.Endpoint, ["projects", options.Project], []);
    }

    private static Uri CreateSnippetsUri(GitLabSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "snippets"],
            [
                new KeyValuePair<string, string>("per_page", SnippetsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateMergeRequestUri(GitLabSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "merge_requests", options.MergeRequestIid.ToString(CultureInfo.InvariantCulture)],
            []);
    }

    private static Uri CreateTreeUri(GitLabSourceOptions options, string gitRef, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "repository", "tree"],
            [
                new KeyValuePair<string, string>("recursive", "true"),
                new KeyValuePair<string, string>("per_page", TreeEntriesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("ref", gitRef),
            ]);
    }

    private static Uri CreateRawFileUri(GitLabSourceOptions options, string path, string gitRef)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "repository", "files", path, "raw"],
            [new KeyValuePair<string, string>("ref", gitRef)]);
    }

    private static Uri CreateSnippetRawUri(GitLabSourceOptions options, long snippetId)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "snippets", snippetId.ToString(CultureInfo.InvariantCulture), "raw"],
            []);
    }

    private static Uri CreateUri(
        Uri endpoint,
        IReadOnlyList<string> pathSegments,
        IReadOnlyList<KeyValuePair<string, string>> query)
    {
        var builder = new UriBuilder(endpoint);
        builder.Path = CombinePath(builder.Path, pathSegments);
        builder.Query = CreateQuery(query);
        return builder.Uri;
    }

    private static string CombinePath(string basePath, IReadOnlyList<string> segments)
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

    private static void WarnUnsuccessfulResponse(
        GitLabSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because GitLab returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool HasNextPage(HttpResponseMessage response, int page, Action<string>? warningSink, string target)
    {
        if (response.Headers.TryGetValues("X-Next-Page", out IEnumerable<string>? nextPageValues))
        {
            foreach (string nextPageValue in nextPageValues)
            {
                if (!string.IsNullOrWhiteSpace(nextPageValue))
                {
                    return HasNextPageWithinLimit(page, warningSink, target);
                }
            }
        }

        if (!response.Headers.TryGetValues("Link", out IEnumerable<string>? values)
            || !values.Any(value => value.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return HasNextPageWithinLimit(page, warningSink, target);
    }

    private static bool HasNextPageWithinLimit(int page, Action<string>? warningSink, string target)
    {
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
            && type.Equals("blob", StringComparison.OrdinalIgnoreCase);
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
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out propertyValue);
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

    private static string GetGroupProjectIdentifier(JsonElement value)
    {
        if (TryGetJsonString(value, "path_with_namespace", out string projectPath))
        {
            return projectPath;
        }

        return TryGetJsonInt64(value, "id", out long projectId) && projectId > 0
            ? projectId.ToString(CultureInfo.InvariantCulture)
            : string.Empty;
    }

    private static string CreateDisplayPath(GitLabSourceOptions options, string itemPath)
    {
        return string.Concat(
            "gitlab/",
            NormalizeRemoteItemPath(options.Project),
            "/",
            NormalizeRemoteItemPath(itemPath));
    }

    private static string CreateSnippetDisplayPath(GitLabSourceOptions options, long snippetId, string fileName)
    {
        string normalizedFileName = fileName.Length == 0
            ? string.Concat("snippet-", snippetId.ToString(CultureInfo.InvariantCulture), ".txt")
            : fileName;
        return string.Concat(
            "gitlab-snippet/",
            NormalizeRemoteItemPath(options.Project),
            "/",
            snippetId.ToString(CultureInfo.InvariantCulture),
            "/",
            NormalizeRemoteItemPath(normalizedFileName));
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

    private static bool IsCancellationRequested(GitLabSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static bool IsCancellationRequested(GitLabGroupSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
