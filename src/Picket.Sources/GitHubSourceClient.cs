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
    private const int ActionArtifactsPerPage = 100;
    private const int GistCommentsPerPage = 100;
    private const int GistsPerPage = 100;
    private const int IssuesPerPage = 100;
    private const int ReleaseAssetsPerPage = 100;
    private const int ReleasesPerPage = 100;
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

        if (options.PullRequestNumber != 0)
        {
            (bool shouldScan, GitHubSourceOptions sourceOptions, string sourceRef) = await ResolvePullRequestSourceAsync(
                options,
                cancellationToken).ConfigureAwait(false);
            if (!shouldScan)
            {
                return sourceFiles;
            }

            await AddRepositoryFilesAsync(sourceOptions, sourceRef, sourceFiles, failOnTreeError: true, cancellationToken).ConfigureAwait(false);
            return sourceFiles;
        }

        string gitRef = options.Ref;
        bool hasRepositoryFiles = true;
        if (gitRef.Length == 0)
        {
            gitRef = await ReadDefaultBranchAsync(options, cancellationToken).ConfigureAwait(false);
            if (gitRef.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping GitHub repository {options.Repository} because it does not have a default branch");
                hasRepositoryFiles = false;
            }
        }

        if (hasRepositoryFiles)
        {
            await AddRepositoryFilesAsync(options, gitRef, sourceFiles, failOnTreeError: true, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeIssues && !IsCancellationRequested(options))
        {
            await AddRepositoryIssueFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeReleases && !IsCancellationRequested(options))
        {
            await AddRepositoryReleaseFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeActionArtifacts && !IsCancellationRequested(options))
        {
            await AddRepositoryActionArtifactFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        return sourceFiles;
    }

    private async Task<(bool ShouldScan, GitHubSourceOptions SourceOptions, string SourceRef)> ResolvePullRequestSourceAsync(
        GitHubSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreatePullRequestUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        string sourceSha = GetNestedString(document.RootElement, "head", "sha");
        if (sourceSha.Length == 0)
        {
            options.WarningSink?.Invoke($"skipping GitHub pull request {options.PullRequestNumber.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository} because its head SHA was not returned");
            return (false, options, string.Empty);
        }

        string sourceRepository = GetNestedString(document.RootElement, "head", "repo", "full_name");
        if (sourceRepository.Length == 0)
        {
            sourceRepository = options.Repository;
        }

        var sourceOptions = new GitHubSourceOptions(
            options.Endpoint,
            sourceRepository,
            options.Credential,
            sourceSha,
            maxFileBytes: options.MaxFileBytes,
            warningSink: options.WarningSink,
            isCancellationRequested: options.IsCancellationRequested);
        return (true, sourceOptions, sourceSha);
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
            }

            var repositoryOptions = new GitHubSourceOptions(
                options.Endpoint,
                string.Concat(options.Organization, "/", name),
                options.Credential,
                gitRef,
                includeIssues: options.IncludeIssues,
                issueState: options.IssueState,
                includeReleases: options.IncludeReleases,
                includeActionArtifacts: options.IncludeActionArtifacts,
                maxFileBytes: options.MaxFileBytes,
                maxArchiveDepth: options.MaxArchiveDepth,
                maxArchiveEntries: options.MaxArchiveEntries,
                maxArchiveBytes: options.MaxArchiveBytes,
                maxArchiveCompressionRatio: options.MaxArchiveCompressionRatio,
                isPathAllowed: options.IsPathAllowed,
                warningSink: options.WarningSink,
                isCancellationRequested: options.IsCancellationRequested);
            if (gitRef.Length != 0)
            {
                await AddRepositoryFilesAsync(repositoryOptions, gitRef, sourceFiles, failOnTreeError: false, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeIssues && !IsCancellationRequested(options))
            {
                await AddRepositoryIssueFilesAsync(repositoryOptions, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeReleases && !IsCancellationRequested(options))
            {
                await AddRepositoryReleaseFilesAsync(repositoryOptions, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeActionArtifacts && !IsCancellationRequested(options))
            {
                await AddRepositoryActionArtifactFilesAsync(repositoryOptions, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates files from GitHub gists selected by the supplied options.
    /// </summary>
    /// <param name="options">The GitHub gist source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateGistFilesAsync(
        GitHubGistSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.ValidateSelector();

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        if (options.GistId.Length != 0)
        {
            await AddGistFilesAsync(options, options.GistId, sourceFiles, cancellationToken).ConfigureAwait(false);
            return sourceFiles;
        }

        await AddPagedGistFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
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

    private async Task AddPagedGistFilesAsync(
        GitHubGistSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = options.IncludeAuthenticatedGists
                ? CreateAuthenticatedGistListUri(options, page)
                : CreateUserGistListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, "skipping GitHub gist enumeration");
                return;
            }

            await AddPagedGistFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddPagedGistFilesAsync(
        GitHubGistSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement gist in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            string gistId = GetString(gist, "id");
            if (gistId.Length == 0)
            {
                continue;
            }

            await AddGistFilesAsync(options, gistId, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddGistFilesAsync(
        GitHubGistSourceOptions options,
        string gistId,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateGistUri(options, gistId);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitHub gist {gistId}");
            return;
        }

        await AddGistFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
    }

    private async Task AddGistFilesAsync(
        GitHubGistSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        JsonElement gist = document.RootElement;
        string gistId = GetString(gist, "id");
        if (gistId.Length == 0)
        {
            return;
        }

        string owner = GetNestedString(gist, "owner", "login");
        if (owner.Length == 0)
        {
            owner = "unknown";
        }

        if (GetBoolean(gist, "truncated"))
        {
            options.WarningSink?.Invoke($"GitHub gist {gistId} file list was truncated by the API");
        }

        if (gist.TryGetProperty("files", out JsonElement files)
            && files.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty file in files.EnumerateObject())
            {
                if (IsCancellationRequested(options))
                {
                    return;
                }

                await AddGistFileAsync(options, owner, gistId, file.Name, file.Value, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }

        if ((!TryGetJsonInt64(gist, "comments", out long comments) || comments > 0)
            && !IsCancellationRequested(options))
        {
            await AddGistCommentFilesAsync(options, owner, gistId, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddGistFileAsync(
        GitHubGistSourceOptions options,
        string owner,
        string gistId,
        string fallbackFileName,
        JsonElement file,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string fileName = GetString(file, "filename");
        if (fileName.Length == 0)
        {
            fileName = fallbackFileName;
        }

        string displayPath = CreateGistFileDisplayPath(owner, gistId, fileName);
        if (options.MaxFileBytes.HasValue
            && TryGetJsonInt64(file, "size", out long size)
            && size > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return;
        }

        if (!GetBoolean(file, "truncated")
            && TryGetJsonStringAllowEmpty(file, "content", out string content))
        {
            AddSyntheticTextFile(options, displayPath, content, sourceFiles);
            return;
        }

        string rawUrl = GetString(file, "raw_url");
        if (rawUrl.Length == 0 || !Uri.TryCreate(rawUrl, UriKind.Absolute, out Uri? rawUri))
        {
            options.WarningSink?.Invoke($"skipping GitHub gist file {displayPath} because the gist API did not return content or raw_url");
            return;
        }

        byte[]? bytes = await DownloadGistRawFileAsync(options, rawUri, displayPath, cancellationToken).ConfigureAwait(false);
        if (bytes is not null)
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
        }
    }

    private async Task AddGistCommentFilesAsync(
        GitHubGistSourceOptions options,
        string owner,
        string gistId,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateGistCommentListUri(options, gistId, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub gist comments for {gistId}");
                return;
            }

            await AddGistCommentFilesAsync(options, owner, gistId, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private static async Task AddGistCommentFilesAsync(
        GitHubGistSourceOptions options,
        string owner,
        string gistId,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement comment in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonInt64(comment, "id", out long commentId))
            {
                continue;
            }

            AddSyntheticTextFile(
                options,
                CreateGistCommentDisplayPath(owner, gistId, commentId),
                CreateGistCommentContent(gistId, commentId, GetString(comment, "body")),
                sourceFiles);
        }
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

    private async Task AddRepositoryIssueFilesAsync(
        GitHubSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateRepositoryIssueListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub issues for repository {options.Repository}");
                return;
            }

            await AddIssueFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddRepositoryReleaseFilesAsync(
        GitHubSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateReleaseListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub releases for repository {options.Repository}");
                return;
            }

            await AddReleaseFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddReleaseFilesAsync(
        GitHubSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement release in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonInt64(release, "id", out long releaseId))
            {
                continue;
            }

            string releaseTag = GetString(release, "tag_name");
            if (releaseTag.Length == 0)
            {
                releaseTag = releaseId.ToString(CultureInfo.InvariantCulture);
            }

            AddSyntheticTextFile(
                options,
                CreateReleaseDisplayPath(options, releaseTag),
                CreateReleaseContent(releaseTag, GetString(release, "name"), GetString(release, "body")),
                sourceFiles);

            if (release.TryGetProperty("assets", out JsonElement assets)
                && assets.ValueKind == JsonValueKind.Array)
            {
                await AddReleaseAssetFilesAsync(options, releaseTag, assets, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
            else if (!IsCancellationRequested(options))
            {
                await AddReleaseAssetFilesAsync(options, releaseId, releaseTag, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task AddReleaseAssetFilesAsync(
        GitHubSourceOptions options,
        long releaseId,
        string releaseTag,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateReleaseAssetListUri(options, releaseId, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub release assets for {options.Repository}@{releaseTag}");
                return;
            }

            using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                await AddReleaseAssetFilesAsync(options, releaseTag, document.RootElement, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddReleaseAssetFilesAsync(
        GitHubSourceOptions options,
        string releaseTag,
        JsonElement assets,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        foreach (JsonElement asset in assets.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            await AddReleaseAssetFileAsync(options, releaseTag, asset, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddReleaseAssetFileAsync(
        GitHubSourceOptions options,
        string releaseTag,
        JsonElement asset,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string assetName = GetString(asset, "name");
        if (assetName.Length == 0)
        {
            assetName = "asset";
        }

        string displayPath = CreateReleaseAssetDisplayPath(options, releaseTag, assetName);
        if (options.MaxFileBytes.HasValue
            && TryGetJsonInt64(asset, "size", out long size)
            && size > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return;
        }

        string assetUrl = GetString(asset, "url");
        if (assetUrl.Length == 0 || !Uri.TryCreate(assetUrl, UriKind.Absolute, out Uri? uri))
        {
            options.WarningSink?.Invoke($"skipping GitHub release asset {displayPath} because the release API did not return an asset URL");
            return;
        }

        byte[]? bytes = await DownloadReleaseAssetAsync(options, uri, displayPath, cancellationToken).ConfigureAwait(false);
        if (bytes is not null)
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
        }
    }

    private async Task AddRepositoryActionArtifactFilesAsync(
        GitHubSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateActionArtifactListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub Actions artifacts for repository {options.Repository}");
                return;
            }

            await AddActionArtifactFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddActionArtifactFilesAsync(
        GitHubSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("artifacts", out JsonElement artifacts)
            || artifacts.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement artifact in artifacts.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            await AddActionArtifactFileAsync(options, artifact, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddActionArtifactFileAsync(
        GitHubSourceOptions options,
        JsonElement artifact,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (!TryGetJsonInt64(artifact, "id", out long artifactId))
        {
            return;
        }

        string artifactName = GetString(artifact, "name");
        if (artifactName.Length == 0)
        {
            artifactName = artifactId.ToString(CultureInfo.InvariantCulture);
        }

        string displayPath = CreateActionArtifactArchiveDisplayPath(options, artifactName, artifactId);
        if (TryGetJsonBoolean(artifact, "expired", out bool expired) && expired)
        {
            options.WarningSink?.Invoke($"skipping expired GitHub Actions artifact {displayPath}");
            return;
        }

        if (options.MaxFileBytes.HasValue
            && TryGetJsonInt64(artifact, "size_in_bytes", out long size)
            && size > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return;
        }

        Uri uri = CreateActionArtifactDownloadUri(options, artifact, artifactId);
        byte[]? bytes = await DownloadActionArtifactArchiveAsync(options, uri, displayPath, cancellationToken).ConfigureAwait(false);
        if (bytes is null)
        {
            return;
        }

        if (options.MaxArchiveDepth == 0)
        {
            options.WarningSink?.Invoke($"skipping GitHub Actions artifact {displayPath} because archive traversal is disabled");
            return;
        }

        var entries = new List<ArchiveEntry>();
        if (!ArchiveReader.TryReadBytesEntries(
            bytes,
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
            options.WarningSink?.Invoke($"skipping GitHub Actions artifact {displayPath} because it is not a readable archive");
            return;
        }

        for (int i = 0; i < entries.Count; i++)
        {
            ArchiveEntry entry = entries[i];
            sourceFiles.Add(new SourceFile(s_remoteFullPath, entry.DisplayPath, entry.Content));
        }
    }

    private async Task AddIssueFilesAsync(
        GitHubSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement issue in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (issue.TryGetProperty("pull_request", out _)
                || !TryGetJsonInt32(issue, "number", out int issueNumber))
            {
                continue;
            }

            AddSyntheticTextFile(
                options,
                CreateIssueDisplayPath(options, issueNumber),
                CreateIssueContent(issueNumber, GetString(issue, "title"), GetString(issue, "body")),
                sourceFiles);

            if (!TryGetJsonInt64(issue, "comments", out long comments)
                || comments > 0)
            {
                await AddIssueCommentFilesAsync(options, issueNumber, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task AddIssueCommentFilesAsync(
        GitHubSourceOptions options,
        int issueNumber,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateIssueCommentListUri(options, issueNumber, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping GitHub issue comments for {options.Repository}#{issueNumber.ToString(CultureInfo.InvariantCulture)}");
                return;
            }

            await AddIssueCommentFilesAsync(options, issueNumber, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(response);
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private static async Task AddIssueCommentFilesAsync(
        GitHubSourceOptions options,
        int issueNumber,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement comment in document.RootElement.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonInt64(comment, "id", out long commentId))
            {
                continue;
            }

            AddSyntheticTextFile(
                options,
                CreateIssueCommentDisplayPath(options, issueNumber, commentId),
                CreateIssueCommentContent(issueNumber, commentId, GetString(comment, "body")),
                sourceFiles);
        }
    }

    private static void AddSyntheticTextFile(
        GitHubSourceOptions options,
        string displayPath,
        string content,
        List<SourceFile> sourceFiles)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        if (options.MaxFileBytes.HasValue && bytes.LongLength > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return;
        }

        sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
    }

    private static void AddSyntheticTextFile(
        GitHubGistSourceOptions options,
        string displayPath,
        string content,
        List<SourceFile> sourceFiles)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        if (options.MaxFileBytes.HasValue && bytes.LongLength > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return;
        }

        sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
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
        GitHubGistSourceOptions options,
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

    private async Task<HttpResponseMessage> SendUnauthenticatedRawAsync(Uri uri, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
        return await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendReleaseAssetAsync(
        GitHubSourceOptions options,
        Uri uri,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Credential);
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

    private async Task<byte[]?> DownloadGistRawFileAsync(
        GitHubGistSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (!IsAllowedGistRawUri(options, uri))
        {
            options.WarningSink?.Invoke($"skipping GitHub gist file {displayPath} because raw_url is not an allowed GitHub raw content endpoint");
            return null;
        }

        using HttpResponseMessage response = await SendUnauthenticatedRawAsync(uri, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitHub gist file {displayPath}");
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

    private async Task<byte[]?> DownloadReleaseAssetAsync(
        GitHubSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (!IsAllowedGitHubApiUri(options.Endpoint, uri))
        {
            options.WarningSink?.Invoke($"skipping GitHub release asset {displayPath} because the asset URL is not an allowed GitHub API endpoint");
            return null;
        }

        using HttpResponseMessage response = await SendReleaseAssetAsync(options, uri, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedReleaseAssetRedirectUri(options, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping GitHub release asset {displayPath} because the redirected download URL is not an allowed GitHub asset endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping GitHub release asset {displayPath}");
                return null;
            }

            return await ReadReleaseAssetContentWithinLimitAsync(redirectedResponse, options, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitHub release asset {displayPath}");
            return null;
        }

        return await ReadReleaseAssetContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadActionArtifactArchiveAsync(
        GitHubSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (!IsAllowedGitHubApiUri(options.Endpoint, uri))
        {
            options.WarningSink?.Invoke($"skipping GitHub Actions artifact {displayPath} because the archive URL is not an allowed GitHub API endpoint");
            return null;
        }

        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedActionArtifactRedirectUri(options, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping GitHub Actions artifact {displayPath} because the redirected download URL is not an allowed GitHub Actions artifact endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping GitHub Actions artifact {displayPath}");
                return null;
            }

            return await ReadActionArtifactArchiveWithinLimitAsync(redirectedResponse, options, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitHub Actions artifact {displayPath}");
            return null;
        }

        return await ReadActionArtifactArchiveWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadReleaseAssetContentWithinLimitAsync(
        HttpResponseMessage response,
        GitHubSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (options.MaxFileBytes.HasValue
            && response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadActionArtifactArchiveWithinLimitAsync(
        HttpResponseMessage response,
        GitHubSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (options.MaxFileBytes.HasValue
            && response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"GitHub file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GitHubGistSourceOptions options,
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

    private static Uri CreateAuthenticatedGistListUri(GitHubGistSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["gists"],
            [
                new KeyValuePair<string, string>("per_page", GistsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateUserGistListUri(GitHubGistSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["users", options.UserName, "gists"],
            [
                new KeyValuePair<string, string>("per_page", GistsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateGistUri(GitHubGistSourceOptions options, string gistId)
    {
        return CreateUri(options.Endpoint, ["gists", gistId], []);
    }

    private static Uri CreateGistCommentListUri(GitHubGistSourceOptions options, string gistId, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["gists", gistId, "comments"],
            [
                new KeyValuePair<string, string>("per_page", GistCommentsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
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

    private static Uri CreateRepositoryIssueListUri(GitHubSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "issues"],
            [
                new KeyValuePair<string, string>("state", options.IssueState),
                new KeyValuePair<string, string>("per_page", IssuesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateReleaseListUri(GitHubSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "releases"],
            [
                new KeyValuePair<string, string>("per_page", ReleasesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateReleaseAssetListUri(GitHubSourceOptions options, long releaseId, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "releases", releaseId.ToString(CultureInfo.InvariantCulture), "assets"],
            [
                new KeyValuePair<string, string>("per_page", ReleaseAssetsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateActionArtifactListUri(GitHubSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "actions", "artifacts"],
            [
                new KeyValuePair<string, string>("per_page", ActionArtifactsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateActionArtifactDownloadUri(GitHubSourceOptions options, JsonElement artifact, long artifactId)
    {
        string archiveUrl = GetString(artifact, "archive_download_url");
        if (archiveUrl.Length != 0
            && Uri.TryCreate(archiveUrl, UriKind.Absolute, out Uri? archiveUri))
        {
            return archiveUri;
        }

        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "actions", "artifacts", artifactId.ToString(CultureInfo.InvariantCulture), "zip"],
            []);
    }

    private static Uri CreateIssueCommentListUri(GitHubSourceOptions options, int issueNumber, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "issues", issueNumber.ToString(CultureInfo.InvariantCulture), "comments"],
            [
                new KeyValuePair<string, string>("per_page", IssuesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreatePullRequestUri(GitHubSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.RepositoryName, "pulls", options.PullRequestNumber.ToString(CultureInfo.InvariantCulture)],
            []);
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

    private static void WarnUnsuccessfulResponse(
        GitHubGistSourceOptions options,
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

    private static bool IsRedirect(HttpResponseMessage response)
    {
        int statusCode = (int)response.StatusCode;
        return statusCode is >= 300 and <= 399;
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

    private static bool TryGetJsonStringAllowEmpty(JsonElement value, string propertyName, out string propertyValue)
    {
        propertyValue = string.Empty;
        if (!value.TryGetProperty(propertyName, out JsonElement property)
            || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        propertyValue = property.GetString() ?? string.Empty;
        return true;
    }

    private static bool TryGetJsonInt64(JsonElement value, string propertyName, out long propertyValue)
    {
        propertyValue = 0;
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out propertyValue);
    }

    private static bool TryGetJsonInt32(JsonElement value, string propertyName, out int propertyValue)
    {
        propertyValue = 0;
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt32(out propertyValue);
    }

    private static bool TryGetJsonBoolean(JsonElement value, string propertyName, out bool propertyValue)
    {
        propertyValue = false;
        if (!value.TryGetProperty(propertyName, out JsonElement property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.True)
        {
            propertyValue = true;
            return true;
        }

        return property.ValueKind == JsonValueKind.False;
    }

    private static string GetString(JsonElement value, string propertyName)
    {
        return TryGetJsonString(value, propertyName, out string propertyValue) ? propertyValue : string.Empty;
    }

    private static string GetNestedString(JsonElement value, string objectPropertyName, string valuePropertyName)
    {
        if (!value.TryGetProperty(objectPropertyName, out JsonElement nested)
            || nested.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(nested, valuePropertyName);
    }

    private static string GetNestedString(
        JsonElement value,
        string firstObjectPropertyName,
        string secondObjectPropertyName,
        string valuePropertyName)
    {
        if (!value.TryGetProperty(firstObjectPropertyName, out JsonElement firstNested)
            || firstNested.ValueKind != JsonValueKind.Object
            || !firstNested.TryGetProperty(secondObjectPropertyName, out JsonElement secondNested)
            || secondNested.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(secondNested, valuePropertyName);
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

    private static string CreateIssueDisplayPath(GitHubSourceOptions options, int issueNumber)
    {
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/issues/",
            issueNumber.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateIssueCommentDisplayPath(GitHubSourceOptions options, int issueNumber, long commentId)
    {
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/issues/",
            issueNumber.ToString(CultureInfo.InvariantCulture),
            "/comments/",
            commentId.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateReleaseDisplayPath(GitHubSourceOptions options, string releaseTag)
    {
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/releases/",
            EscapeDisplaySegment(releaseTag),
            ".md");
    }

    private static string CreateReleaseAssetDisplayPath(GitHubSourceOptions options, string releaseTag, string assetName)
    {
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/releases/",
            EscapeDisplaySegment(releaseTag),
            "/assets/",
            EscapeDisplaySegment(assetName));
    }

    private static string CreateActionArtifactArchiveDisplayPath(GitHubSourceOptions options, string artifactName, long artifactId)
    {
        return string.Concat(
            "github/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.RepositoryName),
            "/actions/artifacts/",
            EscapeDisplaySegment(artifactName),
            "-",
            artifactId.ToString(CultureInfo.InvariantCulture),
            ".zip");
    }

    private static string CreateGistFileDisplayPath(string owner, string gistId, string fileName)
    {
        string normalizedFileName = fileName.Replace('\\', '/').TrimStart('/');
        return string.Concat(
            "github/gists/",
            EscapeDisplaySegment(owner),
            "/",
            EscapeDisplaySegment(gistId),
            "/",
            normalizedFileName);
    }

    private static string CreateGistCommentDisplayPath(string owner, string gistId, long commentId)
    {
        return string.Concat(
            "github/gists/",
            EscapeDisplaySegment(owner),
            "/",
            EscapeDisplaySegment(gistId),
            "/comments/",
            commentId.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateIssueContent(int issueNumber, string title, string body)
    {
        var builder = new StringBuilder();
        builder.Append("# Issue ");
        builder.Append(issueNumber.ToString(CultureInfo.InvariantCulture));
        if (title.Length != 0)
        {
            builder.Append(": ");
            builder.Append(title);
        }

        builder.AppendLine();
        builder.AppendLine();
        if (body.Length != 0)
        {
            builder.AppendLine(body);
        }

        return builder.ToString();
    }

    private static string CreateIssueCommentContent(int issueNumber, long commentId, string body)
    {
        var builder = new StringBuilder();
        builder.Append("# Issue ");
        builder.Append(issueNumber.ToString(CultureInfo.InvariantCulture));
        builder.Append(" comment ");
        builder.Append(commentId.ToString(CultureInfo.InvariantCulture));
        builder.AppendLine();
        builder.AppendLine();
        if (body.Length != 0)
        {
            builder.AppendLine(body);
        }

        return builder.ToString();
    }

    private static string CreateReleaseContent(string releaseTag, string name, string body)
    {
        var builder = new StringBuilder();
        builder.Append("# Release ");
        builder.Append(releaseTag);
        if (name.Length != 0)
        {
            builder.Append(": ");
            builder.Append(name);
        }

        builder.AppendLine();
        builder.AppendLine();
        if (body.Length != 0)
        {
            builder.AppendLine(body);
        }

        return builder.ToString();
    }

    private static string CreateGistCommentContent(string gistId, long commentId, string body)
    {
        var builder = new StringBuilder();
        builder.Append("# Gist ");
        builder.Append(gistId);
        builder.Append(" comment ");
        builder.Append(commentId.ToString(CultureInfo.InvariantCulture));
        builder.AppendLine();
        builder.AppendLine();
        if (body.Length != 0)
        {
            builder.AppendLine(body);
        }

        return builder.ToString();
    }

    private static bool IsAllowedGistRawUri(GitHubGistSourceOptions options, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.Scheme is not "https" and not "http")
        {
            return false;
        }

        bool sameHost = uri.Host.Equals(options.Endpoint.Host, StringComparison.OrdinalIgnoreCase);
        bool subdomainOfEndpoint = uri.Host.EndsWith(string.Concat(".", options.Endpoint.Host), StringComparison.OrdinalIgnoreCase);
        bool publicGitHubRawHost = options.Endpoint.Host.Equals("api.github.com", StringComparison.OrdinalIgnoreCase)
            && uri.Host.Equals("gist.githubusercontent.com", StringComparison.OrdinalIgnoreCase);
        if (!sameHost && !subdomainOfEndpoint && !publicGitHubRawHost)
        {
            return false;
        }

        if (uri.Scheme.Equals("http", StringComparison.Ordinal)
            && !options.Endpoint.Scheme.Equals("http", StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    private static bool IsAllowedGitHubApiUri(Uri endpoint, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !uri.Scheme.Equals(endpoint.Scheme, StringComparison.Ordinal)
            || !uri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || uri.Port != endpoint.Port)
        {
            return false;
        }

        string endpointPath = endpoint.AbsolutePath.TrimEnd('/');
        return endpointPath.Length == 0
            || uri.AbsolutePath.StartsWith(string.Concat(endpointPath, "/"), StringComparison.Ordinal);
    }

    private static bool IsAllowedReleaseAssetRedirectUri(GitHubSourceOptions options, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.Scheme is not "https" and not "http")
        {
            return false;
        }

        if (uri.Scheme.Equals("http", StringComparison.Ordinal)
            && !options.Endpoint.Scheme.Equals("http", StringComparison.Ordinal))
        {
            return false;
        }

        bool sameHost = uri.Host.Equals(options.Endpoint.Host, StringComparison.OrdinalIgnoreCase);
        bool subdomainOfEndpoint = uri.Host.EndsWith(string.Concat(".", options.Endpoint.Host), StringComparison.OrdinalIgnoreCase);
        bool publicGitHubAssetHost = options.Endpoint.Host.Equals("api.github.com", StringComparison.OrdinalIgnoreCase)
            && (uri.Host.Equals("objects.githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase));
        return sameHost || subdomainOfEndpoint || publicGitHubAssetHost;
    }

    private static bool IsAllowedActionArtifactRedirectUri(GitHubSourceOptions options, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.Scheme is not "https" and not "http")
        {
            return false;
        }

        if (uri.Scheme.Equals("http", StringComparison.Ordinal)
            && !options.Endpoint.Scheme.Equals("http", StringComparison.Ordinal))
        {
            return false;
        }

        bool sameHost = uri.Host.Equals(options.Endpoint.Host, StringComparison.OrdinalIgnoreCase);
        bool subdomainOfEndpoint = uri.Host.EndsWith(string.Concat(".", options.Endpoint.Host), StringComparison.OrdinalIgnoreCase);
        bool publicGitHubArtifactHost = options.Endpoint.Host.Equals("api.github.com", StringComparison.OrdinalIgnoreCase)
            && (uri.Host.Equals("objects.githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".blob.core.windows.net", StringComparison.OrdinalIgnoreCase));
        return sameHost || subdomainOfEndpoint || publicGitHubArtifactHost;
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

    private static bool IsCancellationRequested(GitHubGistSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
