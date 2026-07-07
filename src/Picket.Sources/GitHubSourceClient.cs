using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates GitHub repository source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for GitHub requests.</param>
public sealed class GitHubSourceClient(HttpClient httpClient)
{
    private const string ApiVersion = "2022-11-28";
    private const int RepositoriesPerPage = 100;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-github-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates GitHub repository files selected by the supplied options.
    /// </summary>
    /// <param name="options">The GitHub source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateRepositoryFilesAsync(
        GitHubSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        string gitRef = options.Ref;
        if (gitRef.Length == 0)
        {
            gitRef = await ReadDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
            if (gitRef.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping GitHub repository {options.Repository} because it does not have a default branch");
                return sourceFiles;
            }
        }

        await AddRepositoryFilesAsync(options, gitRef, sourceFiles, failOnTreeError: true, cancellationToken).ConfigureAwait(false);
        return sourceFiles;
    }

    /// <summary>
    /// Enumerates files from repositories visible in the supplied GitHub organization.
    /// </summary>
    /// <param name="options">The GitHub organization source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateOrganizationRepositoryFilesAsync(
        GitHubOrganizationSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        List<(string Name, string DefaultBranch)> repositories = await ListOrganizationRepositoriesAsync(options, cancellationToken).ConfigureAwait(false);
        for (int i = 0; i < repositories.Count; i++)
        {
            if (IsCancellationRequested(options))
            {
                break;
            }

            (string name, string defaultBranch) = repositories[i];
            string gitRef = options.Ref.Length == 0 ? defaultBranch : options.Ref;
            if (gitRef.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping GitHub repository {options.Organization}/{name} because it does not have a default branch");
                continue;
            }

            var repositoryOptions = new GitHubSourceOptions(
                options.Endpoint,
                string.Concat(options.Organization, "/", name),
                options.Credential,
                gitRef,
                options.MaxFileBytes,
                options.WarningSink,
                options.IsCancellationRequested);
            await AddRepositoryFilesAsync(repositoryOptions, gitRef, sourceFiles, failOnTreeError: false, cancellationToken).ConfigureAwait(false);
        }

        return sourceFiles;
    }

    private async Task AddRepositoryFilesAsync(
        GitHubSourceOptions options,
        string gitRef,
        List<SourceFile> sourceFiles,
        bool failOnTreeError,
        CancellationToken cancellationToken)
    {
        Uri treeUri = CreateTreeUri(options, gitRef);
        using HttpResponseMessage treeResponse = await SendAsync(options, treeUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!treeResponse.IsSuccessStatusCode)
        {
            if (failOnTreeError)
            {
                treeResponse.EnsureSuccessStatusCode();
            }

            WarnUnsuccessfulResponse(options, treeResponse, $"skipping GitHub repository {options.Repository}");
            return;
        }

        await AddTreeFilesAsync(options, gitRef, treeResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
    }

    private async Task<List<(string Name, string DefaultBranch)>> ListOrganizationRepositoriesAsync(
        GitHubOrganizationSourceOptions options,
        CancellationToken cancellationToken)
    {
        var repositories = new List<(string Name, string DefaultBranch)>();
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateOrganizationRepositoryListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await AddOrganizationRepositoriesAsync(options, response, repositories, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));

        return repositories;
    }

    private static async Task AddOrganizationRepositoriesAsync(
        GitHubOrganizationSourceOptions options,
        HttpResponseMessage response,
        List<(string Name, string DefaultBranch)> repositories,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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

            string name = GetString(item, "name");
            if (name.Length == 0)
            {
                continue;
            }

            repositories.Add((name, GetString(item, "default_branch")));
        }
    }

    private async Task<string> ReadDefaultBranchAsync(GitHubSourceOptions options, CancellationToken cancellationToken)
    {
        Uri uri = CreateRepositoryUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        return GetString(document.RootElement, "default_branch");
    }

    private async Task AddTreeFilesAsync(
        GitHubSourceOptions options,
        string gitRef,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (GetBoolean(document.RootElement, "truncated"))
        {
            options.WarningSink?.Invoke($"GitHub tree for {options.Repository} was truncated by the API");
        }

        if (!document.RootElement.TryGetProperty("tree", out JsonElement tree)
            || tree.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in tree.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!IsBlobItem(item) || !TryGetJsonString(item, "path", out string path))
            {
                continue;
            }

            if (options.MaxFileBytes.HasValue
                && TryGetJsonInt64(item, "size", out long treeSize)
                && treeSize > options.MaxFileBytes.Value)
            {
                options.WarningSink?.Invoke($"GitHub file byte limit skipped {CreateDisplayPath(options, path)}");
                continue;
            }

            Uri downloadUri = CreateContentDownloadUri(options, path, gitRef);
            string displayPath = CreateDisplayPath(options, path);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadFileAsync(
        GitHubSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitHub file {displayPath}");
            return null;
        }

        if (options.MaxFileBytes.HasValue
            && response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GitHubSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(options.Credential, uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GitHubOrganizationSourceOptions options,
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
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptRaw ? "application/vnd.github.raw" : "application/vnd.github+json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
        request.Headers.Add("X-GitHub-Api-Version", ApiVersion);
        return await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GitHubSourceOptions options,
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

                if (options.MaxFileBytes.HasValue)
                {
                    long projectedLength = memory.Length + read;
                    if (projectedLength > options.MaxFileBytes.Value)
                    {
                        options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
                        return null;
                    }
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

    private static Uri CreateRepositoryUri(GitHubSourceOptions options)
    {
        return CreateUri(options.Endpoint, ["repos", options.Owner, options.RepositoryName], []);
    }

    private static Uri CreateOrganizationRepositoryListUri(GitHubOrganizationSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["orgs", options.Organization, "repos"],
            [
                new KeyValuePair<string, string>("type", options.RepositoryType),
                new KeyValuePair<string, string>("per_page", RepositoriesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateTreeUri(GitHubSourceOptions options, string gitRef)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "git", "trees", gitRef],
            [new KeyValuePair<string, string>("recursive", "1")]);
    }

    private static Uri CreateContentDownloadUri(GitHubSourceOptions options, string path, string gitRef)
    {
        var segments = new List<string>
        {
            "repos",
            options.Owner,
            options.RepositoryName,
            "contents",
        };
        foreach (string segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            segments.Add(segment);
        }

        return CreateUri(options.Endpoint, segments, [new KeyValuePair<string, string>("ref", gitRef)]);
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
        GitHubSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because GitHub returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool HasNextPage(HttpResponseMessage response)
    {
        return response.Headers.TryGetValues("Link", out IEnumerable<string>? values)
            && values.Any(value => value.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase));
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

    private static bool GetBoolean(JsonElement value, string propertyName)
    {
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.True;
    }

    private static string CreateDisplayPath(GitHubSourceOptions options, string itemPath)
    {
        string normalizedItemPath = itemPath.Replace('\\', '/').TrimStart('/');
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/",
            normalizedItemPath);
    }

    private static string EscapeDisplaySegment(string value)
    {
        return Uri.EscapeDataString(value).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCancellationRequested(GitHubSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static bool IsCancellationRequested(GitHubOrganizationSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
