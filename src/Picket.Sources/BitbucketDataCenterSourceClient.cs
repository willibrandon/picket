using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Bitbucket Data Center repository source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for Bitbucket Data Center requests.</param>
public sealed class BitbucketDataCenterSourceClient(HttpClient httpClient)
{
    private const int EntriesPerPage = 100;
    private const int MaxPaginationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-bitbucket-data-center-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates files from the repository or project selected by the supplied options.
    /// </summary>
    /// <param name="options">The Bitbucket Data Center source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateFilesAsync(
        BitbucketDataCenterSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        if (options.RepositorySlug.Length == 0)
        {
            await AddProjectRepositoryFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await TryAddSelectedRepositoryFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        return sourceFiles;
    }

    private async Task AddProjectRepositoryFilesAsync(
        BitbucketDataCenterSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int pageCount = 0;
        int start = 0;
        while (!IsCancellationRequested(options))
        {
            if (pageCount == MaxPaginationPages)
            {
                options.WarningSink?.Invoke($"stopping Bitbucket Data Center project {options.ProjectKey} repository enumeration after {MaxPaginationPages} pages");
                return;
            }

            pageCount++;
            Uri repositoriesUri = CreateProjectRepositoriesUri(options, start);
            using HttpResponseMessage response = await SendAsync(options, repositoriesUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket Data Center project {options.ProjectKey}");
                return;
            }

            JsonDocument document;
            try
            {
                document = await RemoteJsonDocumentReader.ReadAsync(
                    response.Content,
                    "Bitbucket Data Center source metadata",
                    options.WarningSink,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (RemoteMetadataTooLargeException)
            {
                return;
            }
            catch (JsonException)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket Data Center project {options.ProjectKey} because repository metadata was invalid");
                return;
            }

            using (document)
            {
                JsonElement root = document.RootElement;
                if (root.TryGetProperty("values", out JsonElement values) && values.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement item in values.EnumerateArray())
                    {
                        if (IsCancellationRequested(options))
                        {
                            return;
                        }

                        string repositorySlug = GetString(item, "slug");
                        if (repositorySlug.Length == 0)
                        {
                            repositorySlug = GetString(item, "name");
                        }

                        BitbucketDataCenterSourceOptions repositoryOptions;
                        try
                        {
                            repositoryOptions = options.CreateForRepository(options.ProjectKey, repositorySlug, options.Ref);
                        }
                        catch (ArgumentException)
                        {
                            options.WarningSink?.Invoke($"skipping an invalid repository returned for Bitbucket Data Center project {options.ProjectKey}");
                            continue;
                        }

                        await TryAddSelectedRepositoryFilesAsync(repositoryOptions, sourceFiles, cancellationToken).ConfigureAwait(false);
                    }
                }

                if (!TryGetNextPageStart(root, start, pageCount, options, $"Bitbucket Data Center project {options.ProjectKey} repository enumeration", out int nextStart))
                {
                    return;
                }

                start = nextStart;
            }
        }
    }

    private async Task TryAddSelectedRepositoryFilesAsync(
        BitbucketDataCenterSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string target = string.Concat(options.ProjectKey, "/", options.RepositorySlug);
        try
        {
            if (options.PullRequestId != 0)
            {
                (bool shouldScan, BitbucketDataCenterSourceOptions sourceOptions, string sourceCommit) = await ResolvePullRequestSourceAsync(
                    options,
                    cancellationToken).ConfigureAwait(false);
                if (shouldScan)
                {
                    await AddRepositoryFilesAsync(sourceOptions, sourceCommit, sourceFiles, cancellationToken).ConfigureAwait(false);
                }

                return;
            }

            string resolvedCommit = await ResolveCommitAsync(options, cancellationToken).ConfigureAwait(false);
            if (resolvedCommit.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket Data Center repository {target} because no scan revision could be resolved");
                return;
            }

            await AddRepositoryFilesAsync(options, resolvedCommit, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
        catch (RemoteMetadataTooLargeException)
        {
        }
        catch (JsonException)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket Data Center repository {target} because provider metadata was invalid");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket Data Center repository {target} because source data could not be read");
        }
    }

    private async Task<(bool ShouldScan, BitbucketDataCenterSourceOptions SourceOptions, string Commit)> ResolvePullRequestSourceAsync(
        BitbucketDataCenterSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri pullRequestUri = CreatePullRequestUri(options);
        using HttpResponseMessage response = await SendAsync(options, pullRequestUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping Bitbucket Data Center pull request {options.ProjectKey}/{options.RepositorySlug}#{options.PullRequestId}");
            return (false, options, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            "Bitbucket Data Center source metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("fromRef", out JsonElement fromRef)
            || fromRef.ValueKind != JsonValueKind.Object)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket Data Center pull request {options.ProjectKey}/{options.RepositorySlug}#{options.PullRequestId} because source metadata was incomplete");
            return (false, options, string.Empty);
        }

        string commit = GetString(fromRef, "latestCommit");
        string projectKey = string.Empty;
        string repositorySlug = string.Empty;
        if (fromRef.TryGetProperty("repository", out JsonElement repository) && repository.ValueKind == JsonValueKind.Object)
        {
            repositorySlug = GetString(repository, "slug");
            if (repository.TryGetProperty("project", out JsonElement project) && project.ValueKind == JsonValueKind.Object)
            {
                projectKey = GetString(project, "key");
            }
        }

        if (commit.Length == 0 || projectKey.Length == 0 || repositorySlug.Length == 0)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket Data Center pull request {options.ProjectKey}/{options.RepositorySlug}#{options.PullRequestId} because source metadata was incomplete");
            return (false, options, string.Empty);
        }

        try
        {
            return (true, options.CreateForRepository(projectKey, repositorySlug, commit), commit);
        }
        catch (ArgumentException)
        {
            options.WarningSink?.Invoke($"skipping Bitbucket Data Center pull request {options.ProjectKey}/{options.RepositorySlug}#{options.PullRequestId} because source repository metadata was invalid");
            return (false, options, string.Empty);
        }
    }

    private async Task<string> ResolveCommitAsync(
        BitbucketDataCenterSourceOptions options,
        CancellationToken cancellationToken)
    {
        if (IsLikelyCommitId(options.Ref))
        {
            return options.Ref;
        }

        if (options.Ref.Length != 0)
        {
            return await ResolveRefCommitAsync(options, options.Ref, cancellationToken).ConfigureAwait(false);
        }

        (string commit, string branch) = await ReadDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
        if (commit.Length != 0)
        {
            return commit;
        }

        return branch.Length == 0
            ? string.Empty
            : await ResolveRefCommitAsync(options, branch, cancellationToken).ConfigureAwait(false);
    }

    private async Task<(string Commit, string Branch)> ReadDefaultBranchAsync(
        BitbucketDataCenterSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri defaultBranchUri = CreateDefaultBranchUri(options, deprecated: false);
        using HttpResponseMessage response = await SendAsync(options, defaultBranchUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return await ReadDeprecatedDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping default branch for Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug}");
            return (string.Empty, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            "Bitbucket Data Center source metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        return ReadBranchIdentity(document.RootElement);
    }

    private async Task<(string Commit, string Branch)> ReadDeprecatedDefaultBranchAsync(
        BitbucketDataCenterSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri defaultBranchUri = CreateDefaultBranchUri(options, deprecated: true);
        using HttpResponseMessage response = await SendAsync(options, defaultBranchUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping default branch for Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug}");
            return (string.Empty, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            "Bitbucket Data Center source metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        return ReadBranchIdentity(document.RootElement);
    }

    private async Task<string> ResolveRefCommitAsync(
        BitbucketDataCenterSourceOptions options,
        string gitRef,
        CancellationToken cancellationToken)
    {
        Uri commitsUri = CreateCommitsUri(options, gitRef);
        using HttpResponseMessage response = await SendAsync(options, commitsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping revision for Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug}");
            return string.Empty;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
            response.Content,
            "Bitbucket Data Center source metadata",
            options.WarningSink,
            cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("values", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array
            || values.GetArrayLength() == 0)
        {
            return string.Empty;
        }

        JsonElement commit = values[0];
        return GetString(commit, "id");
    }

    private async Task AddRepositoryFilesAsync(
        BitbucketDataCenterSourceOptions options,
        string commit,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        var seenPaths = new HashSet<string>(StringComparer.Ordinal);
        int pageCount = 0;
        int start = 0;
        while (!IsCancellationRequested(options))
        {
            if (pageCount == MaxPaginationPages)
            {
                options.WarningSink?.Invoke($"stopping Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug} file enumeration after {MaxPaginationPages} pages");
                return;
            }

            pageCount++;
            Uri filesUri = CreateFilesUri(options, commit, start);
            using HttpResponseMessage response = await SendAsync(options, filesUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(
                response.Content,
                "Bitbucket Data Center source metadata",
                options.WarningSink,
                cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            if (root.TryGetProperty("values", out JsonElement values) && values.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in values.EnumerateArray())
                {
                    if (IsCancellationRequested(options))
                    {
                        return;
                    }

                    string providerPath = item.ValueKind == JsonValueKind.String
                        ? item.GetString() ?? string.Empty
                        : GetString(item, "path");
                    string normalizedPath = NormalizeProviderPath(providerPath);
                    if (normalizedPath.Length == 0 || !seenPaths.Add(normalizedPath))
                    {
                        continue;
                    }

                    string displayPath = CreateDisplayPath(options.ProjectKey, options.RepositorySlug, normalizedPath);
                    if (options.IsPathAllowed?.Invoke(displayPath) == true)
                    {
                        continue;
                    }

                    Uri rawUri = CreateRawFileUri(options, commit, normalizedPath);
                    byte[]? content = await DownloadFileAsync(options, rawUri, displayPath, cancellationToken).ConfigureAwait(false);
                    if (content is not null)
                    {
                        sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
                    }
                }
            }

            if (!TryGetNextPageStart(root, start, pageCount, options, $"Bitbucket Data Center repository {options.ProjectKey}/{options.RepositorySlug} file enumeration", out int nextStart))
            {
                return;
            }

            start = nextStart;
        }
    }

    private async Task<byte[]?> DownloadFileAsync(
        BitbucketDataCenterSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket Data Center file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength is long contentLength && contentLength > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Bitbucket Data Center file byte limit skipped {displayPath}");
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

                if (memory.Length + read > options.MaxFileBytes)
                {
                    options.WarningSink?.Invoke($"Bitbucket Data Center file byte limit skipped {displayPath}");
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

    private async Task<HttpResponseMessage> SendAsync(
        BitbucketDataCenterSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        AuthenticationHeaderValue authorization = CreateAuthorizationHeader(options);
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptRaw ? "application/octet-stream" : "application/json"));
                request.Headers.Authorization = authorization;
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static AuthenticationHeaderValue CreateAuthorizationHeader(BitbucketDataCenterSourceOptions options)
    {
        return options.CredentialKind switch
        {
            BitbucketDataCenterCredentialKind.BearerToken => new AuthenticationHeaderValue("Bearer", options.Credential),
            BitbucketDataCenterCredentialKind.Basic => new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(options.Username, ":", options.Credential)))),
            _ => throw new ArgumentOutOfRangeException(nameof(options), options.CredentialKind, "Unsupported Bitbucket Data Center credential kind."),
        };
    }

    private static bool TryGetNextPageStart(
        JsonElement root,
        int currentStart,
        int pageCount,
        BitbucketDataCenterSourceOptions options,
        string target,
        out int nextStart)
    {
        nextStart = 0;
        if (root.TryGetProperty("isLastPage", out JsonElement isLastPage)
            && isLastPage.ValueKind is JsonValueKind.True)
        {
            return false;
        }

        if (pageCount == MaxPaginationPages)
        {
            options.WarningSink?.Invoke($"stopping {target} after {MaxPaginationPages} pages");
            return false;
        }

        if (!root.TryGetProperty("nextPageStart", out JsonElement nextPageStart)
            || nextPageStart.ValueKind != JsonValueKind.Number
            || !nextPageStart.TryGetInt32(out nextStart)
            || nextStart <= currentStart)
        {
            options.WarningSink?.Invoke($"stopping {target} because Bitbucket Data Center returned an invalid pagination cursor");
            return false;
        }

        return true;
    }

    private static (string Commit, string Branch) ReadBranchIdentity(JsonElement root)
    {
        string commit = GetString(root, "latestCommit");
        if (commit.Length == 0)
        {
            commit = GetString(root, "latestChangeset");
        }

        string branch = GetString(root, "id");
        if (branch.Length == 0)
        {
            branch = GetString(root, "displayId");
        }

        return (commit, branch);
    }

    private static bool IsLikelyCommitId(string value)
    {
        return value.Length is 40 or 64 && value.All(Uri.IsHexDigit);
    }

    private static bool IsCancellationRequested(BitbucketDataCenterSourceOptions options)
    {
        return options.IsCancellationRequested?.Invoke() == true;
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }

    private static string NormalizeProviderPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        string[] segments = value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < segments.Length; i++)
        {
            string segment = segments[i];
            if (segment is "." or "..")
            {
                segments[i] = "_";
                continue;
            }

            char[] characters = segment.ToCharArray();
            for (int characterIndex = 0; characterIndex < characters.Length; characterIndex++)
            {
                if (char.IsControl(characters[characterIndex]))
                {
                    characters[characterIndex] = '_';
                }
            }

            segments[i] = new string(characters);
        }

        return string.Join('/', segments);
    }

    private static string CreateDisplayPath(string projectKey, string repositorySlug, string path)
    {
        return string.Concat(
            "bitbucket-data-center/",
            NormalizeDisplaySegment(projectKey),
            "/",
            NormalizeDisplaySegment(repositorySlug),
            "/",
            path);
    }

    private static string NormalizeDisplaySegment(string value)
    {
        return value is "." or ".." ? "_" : value.Replace('/', '_').Replace('\\', '_');
    }

    private static Uri CreateProjectRepositoriesUri(BitbucketDataCenterSourceOptions options, int start)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.ProjectKey, "repos"],
            itemPath: null,
            [
                new KeyValuePair<string, string>("limit", EntriesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("start", start.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreatePullRequestUri(BitbucketDataCenterSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.ProjectKey, "repos", options.RepositorySlug, "pull-requests", options.PullRequestId.ToString(CultureInfo.InvariantCulture)],
            itemPath: null,
            query: []);
    }

    private static Uri CreateDefaultBranchUri(BitbucketDataCenterSourceOptions options, bool deprecated)
    {
        string[] segments = deprecated
            ? ["projects", options.ProjectKey, "repos", options.RepositorySlug, "branches", "default"]
            : ["projects", options.ProjectKey, "repos", options.RepositorySlug, "default-branch"];
        return CreateUri(options.Endpoint, segments, itemPath: null, query: []);
    }

    private static Uri CreateCommitsUri(BitbucketDataCenterSourceOptions options, string gitRef)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.ProjectKey, "repos", options.RepositorySlug, "commits"],
            itemPath: null,
            [
                new KeyValuePair<string, string>("limit", "1"),
                new KeyValuePair<string, string>("until", gitRef),
            ]);
    }

    private static Uri CreateFilesUri(BitbucketDataCenterSourceOptions options, string commit, int start)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.ProjectKey, "repos", options.RepositorySlug, "files"],
            itemPath: null,
            [
                new KeyValuePair<string, string>("at", commit),
                new KeyValuePair<string, string>("limit", EntriesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("start", start.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateRawFileUri(BitbucketDataCenterSourceOptions options, string commit, string path)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.ProjectKey, "repos", options.RepositorySlug, "raw"],
            path,
            [new KeyValuePair<string, string>("at", commit)]);
    }

    private static Uri CreateUri(
        Uri endpoint,
        string[] pathSegments,
        string? itemPath,
        KeyValuePair<string, string>[] query)
    {
        var builder = new StringBuilder(endpoint.AbsoluteUri.TrimEnd('/'));
        for (int i = 0; i < pathSegments.Length; i++)
        {
            builder.Append('/');
            builder.Append(Uri.EscapeDataString(pathSegments[i]));
        }

        if (!string.IsNullOrEmpty(itemPath))
        {
            string[] itemSegments = itemPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < itemSegments.Length; i++)
            {
                builder.Append('/');
                builder.Append(Uri.EscapeDataString(itemSegments[i]));
            }
        }

        if (query.Length != 0)
        {
            builder.Append('?');
            for (int i = 0; i < query.Length; i++)
            {
                if (i != 0)
                {
                    builder.Append('&');
                }

                builder.Append(Uri.EscapeDataString(query[i].Key));
                builder.Append('=');
                builder.Append(Uri.EscapeDataString(query[i].Value));
            }
        }

        return new Uri(builder.ToString(), UriKind.Absolute);
    }

    private static void WarnUnsuccessfulResponse(
        BitbucketDataCenterSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Create(
            CultureInfo.InvariantCulture,
            $"{target} because Bitbucket Data Center returned HTTP {(int)response.StatusCode}"));
    }
}
