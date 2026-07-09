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
    private const int IssuesPerPage = 100;
    private const int MaxPaginationPages = 1000;
    private const int RepositoriesPerPage = 100;
    private const int ReleasesPerPage = 100;
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
            if (options.PullRequestId != 0)
            {
                (bool shouldScan, GiteaSourceOptions sourceOptions, string sourceRef) = await ResolvePullRequestSourceAsync(
                    options,
                    cancellationToken).ConfigureAwait(false);
                if (!shouldScan)
                {
                    return sourceFiles;
                }

                string sourceTreeRef = await ResolveTreeRefAsync(sourceOptions, sourceRef, cancellationToken).ConfigureAwait(false);
                await AddRepositoryFilesAsync(sourceOptions, sourceRef, sourceTreeRef, sourceFiles, cancellationToken).ConfigureAwait(false);
                return sourceFiles;
            }

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

            await AddSelectedRepositoryFilesAsync(options, gitRef, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates files from repositories visible in the supplied Gitea organization.
    /// </summary>
    /// <param name="options">The Gitea organization source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateOrganizationRepositoryFilesAsync(
        GiteaOrganizationSourceOptions options,
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
            List<(string Repository, string DefaultBranch)> repositories = await ListOrganizationRepositoriesAsync(options, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < repositories.Count; i++)
            {
                if (IsCancellationRequested(options))
                {
                    break;
                }

                (string repository, string defaultBranch) = repositories[i];
                string gitRef = options.Ref.Length == 0 ? defaultBranch : options.Ref;
                if (gitRef.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Gitea repository {repository} because it does not have a default branch");
                    continue;
                }

                if (TryCreateRepositoryOptions(options, repository, gitRef, out GiteaSourceOptions? repositoryOptions)
                    && repositoryOptions is not null)
                {
                    await AddSelectedRepositoryFilesAsync(repositoryOptions, gitRef, sourceFiles, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates files from repositories visible for the supplied Gitea user.
    /// </summary>
    /// <param name="options">The Gitea user source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateUserRepositoryFilesAsync(
        GiteaUserSourceOptions options,
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
            List<(string Repository, string DefaultBranch)> repositories = await ListUserRepositoriesAsync(options, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < repositories.Count; i++)
            {
                if (IsCancellationRequested(options))
                {
                    break;
                }

                (string repository, string defaultBranch) = repositories[i];
                string gitRef = options.Ref.Length == 0 ? defaultBranch : options.Ref;
                if (gitRef.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Gitea repository {repository} because it does not have a default branch");
                    continue;
                }

                if (TryCreateRepositoryOptions(options, repository, gitRef, out GiteaSourceOptions? repositoryOptions)
                    && repositoryOptions is not null)
                {
                    await AddSelectedRepositoryFilesAsync(repositoryOptions, gitRef, sourceFiles, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates one exact Gitea generic package file selected by the supplied options.
    /// </summary>
    /// <param name="options">The Gitea generic package source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateGenericPackageFileAsync(
        GiteaGenericPackageSourceOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var sourceFiles = new List<SourceFile>();
        if (IsCancellationRequested(options))
        {
            return sourceFiles;
        }

        string displayPath = CreateGenericPackageFileDisplayPath(options);
        if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
        {
            return sourceFiles;
        }

        Uri uri = CreateGenericPackageFileUri(options);
        byte[]? content = await DownloadGenericPackageFileAsync(options, uri, displayPath, cancellationToken).ConfigureAwait(false);
        if (content is not null)
        {
            AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
        }

        return sourceFiles;
    }

    private async Task<List<(string Repository, string DefaultBranch)>> ListOrganizationRepositoriesAsync(
        GiteaOrganizationSourceOptions options,
        CancellationToken cancellationToken)
    {
        var repositories = new List<(string Repository, string DefaultBranch)>();
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateOrganizationRepositoryListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options.Credential, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options.WarningSink, response, $"skipping Gitea organization {options.Organization} repositories");
                return repositories;
            }

            int repositoryCount = await AddRepositoryListEntriesAsync(response, options.Organization, repositories, options.WarningSink, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextListPage(response, page, repositoryCount, RepositoriesPerPage, options.WarningSink, $"Gitea organization {options.Organization} repository enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));

        return repositories;
    }

    private async Task<List<(string Repository, string DefaultBranch)>> ListUserRepositoriesAsync(
        GiteaUserSourceOptions options,
        CancellationToken cancellationToken)
    {
        var repositories = new List<(string Repository, string DefaultBranch)>();
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateUserRepositoryListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options.Credential, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options.WarningSink, response, $"skipping Gitea user {options.UserName} repositories");
                return repositories;
            }

            int repositoryCount = await AddRepositoryListEntriesAsync(response, options.UserName, repositories, options.WarningSink, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextListPage(response, page, repositoryCount, RepositoriesPerPage, options.WarningSink, $"Gitea user {options.UserName} repository enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));

        return repositories;
    }

    private static async Task<int> AddRepositoryListEntriesAsync(
        HttpResponseMessage response,
        string fallbackOwner,
        List<(string Repository, string DefaultBranch)> repositories,
        Action<string>? warningSink,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", warningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int repositoryCount = 0;
        foreach (JsonElement repository in document.RootElement.EnumerateArray())
        {
            repositoryCount++;
            if (TryCreateRepositoryIdentifier(repository, fallbackOwner, out string repositoryIdentifier))
            {
                repositories.Add((repositoryIdentifier, GetString(repository, "default_branch")));
            }
        }

        return repositoryCount;
    }

    private async Task AddSelectedRepositoryFilesAsync(
        GiteaSourceOptions options,
        string gitRef,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string treeRef = await ResolveTreeRefAsync(options, gitRef, cancellationToken).ConfigureAwait(false);
        await AddRepositoryFilesAsync(options, gitRef, treeRef, sourceFiles, cancellationToken).ConfigureAwait(false);
        if (options.IncludeIssues && !IsCancellationRequested(options))
        {
            await AddRepositoryIssueFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeReleases && !IsCancellationRequested(options))
        {
            await AddRepositoryReleaseFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool TryCreateRepositoryOptions(
        GiteaOrganizationSourceOptions options,
        string repository,
        string gitRef,
        out GiteaSourceOptions? repositoryOptions)
    {
        try
        {
            repositoryOptions = options.CreateRepositoryOptions(repository, gitRef);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            options.WarningSink?.Invoke($"skipping Gitea repository {repository} because it was invalid: {ex.Message}");
            repositoryOptions = null;
            return false;
        }
    }

    private static bool TryCreateRepositoryOptions(
        GiteaUserSourceOptions options,
        string repository,
        string gitRef,
        out GiteaSourceOptions? repositoryOptions)
    {
        try
        {
            repositoryOptions = options.CreateRepositoryOptions(repository, gitRef);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            options.WarningSink?.Invoke($"skipping Gitea repository {repository} because it was invalid: {ex.Message}");
            repositoryOptions = null;
            return false;
        }
    }

    private async Task<(bool ShouldScan, GiteaSourceOptions SourceOptions, string SourceRef)> ResolvePullRequestSourceAsync(
        GiteaSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreatePullRequestUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping Gitea pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository}");
            return (false, options, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        string sourceRef = GetNestedString(document.RootElement, "head", "sha");
        if (sourceRef.Length == 0)
        {
            sourceRef = GetNestedString(document.RootElement, "head", "ref");
        }

        if (sourceRef.Length == 0)
        {
            options.WarningSink?.Invoke($"skipping Gitea pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository} because its source head was not returned");
            return (false, options, string.Empty);
        }

        GiteaSourceOptions sourceOptions = options;
        string sourceRepository = GetNestedString(document.RootElement, "head", "repo", "full_name");
        if (sourceRepository.Length != 0 && !sourceRepository.Equals(options.Repository, StringComparison.Ordinal))
        {
            try
            {
                sourceOptions = options.CreateForRepository(sourceRepository);
            }
            catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
            {
                options.WarningSink?.Invoke($"skipping Gitea pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {options.Repository} because its source repository was invalid: {ex.Message}");
                return (false, options, string.Empty);
            }
        }

        return (true, sourceOptions, sourceRef);
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

    private async Task AddRepositoryIssueFilesAsync(
        GiteaSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        var issueNumbersWithComments = new HashSet<int>();
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateRepositoryIssueListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Gitea issues for repository {options.Repository}");
                return;
            }

            int issueCount = await AddIssueFilesAsync(options, response, issueNumbersWithComments, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextListPage(response, page, issueCount, IssuesPerPage, options.WarningSink, $"Gitea issue enumeration for {options.Repository}");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));

        if (issueNumbersWithComments.Count != 0 && !IsCancellationRequested(options))
        {
            await AddIssueCommentFilesAsync(options, issueNumbersWithComments, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<int> AddIssueFilesAsync(
        GiteaSourceOptions options,
        HttpResponseMessage response,
        HashSet<int> issueNumbersWithComments,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int issueCount = 0;
        foreach (JsonElement issue in document.RootElement.EnumerateArray())
        {
            issueCount++;
            if (IsCancellationRequested(options))
            {
                return issueCount;
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
                issueNumbersWithComments.Add(issueNumber);
            }
        }

        return issueCount;
    }

    private async Task AddIssueCommentFilesAsync(
        GiteaSourceOptions options,
        HashSet<int> issueNumbers,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri uri = CreateRepositoryIssueCommentListUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Gitea issue comments for repository {options.Repository}");
                return;
            }

            int commentCount = await AddIssueCommentFilesAsync(options, issueNumbers, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextListPage(response, page, commentCount, IssuesPerPage, options.WarningSink, $"Gitea issue comment enumeration for {options.Repository}");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task<int> AddIssueCommentFilesAsync(
        GiteaSourceOptions options,
        HashSet<int> issueNumbers,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int commentCount = 0;
        foreach (JsonElement comment in document.RootElement.EnumerateArray())
        {
            commentCount++;
            if (IsCancellationRequested(options))
            {
                return commentCount;
            }

            if (!TryGetJsonInt64(comment, "id", out long commentId)
                || !TryGetIssueNumber(comment, out int issueNumber)
                || !issueNumbers.Contains(issueNumber))
            {
                continue;
            }

            AddSyntheticTextFile(
                options,
                CreateIssueCommentDisplayPath(options, issueNumber, commentId),
                CreateIssueCommentContent(issueNumber, commentId, GetString(comment, "body")),
                sourceFiles);
        }

        return commentCount;
    }

    private async Task AddRepositoryReleaseFilesAsync(
        GiteaSourceOptions options,
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
                WarnUnsuccessfulResponse(options, response, $"skipping Gitea releases for repository {options.Repository}");
                return;
            }

            int releaseCount = await AddReleaseFilesAsync(options, response, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextListPage(response, page, releaseCount, ReleasesPerPage, options.WarningSink, $"Gitea release enumeration for {options.Repository}");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task<int> AddReleaseFilesAsync(
        GiteaSourceOptions options,
        HttpResponseMessage response,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        int releaseCount = 0;
        foreach (JsonElement release in document.RootElement.EnumerateArray())
        {
            releaseCount++;
            if (IsCancellationRequested(options))
            {
                return releaseCount;
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

        return releaseCount;
    }

    private async Task AddReleaseAssetFilesAsync(
        GiteaSourceOptions options,
        long releaseId,
        string releaseTag,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateReleaseAssetListUri(options, releaseId);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Gitea release assets for {options.Repository}@{releaseTag}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Gitea source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            await AddReleaseAssetFilesAsync(options, releaseTag, document.RootElement, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddReleaseAssetFilesAsync(
        GiteaSourceOptions options,
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
        GiteaSourceOptions options,
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
        if (TryGetJsonInt64(asset, "size", out long size)
            && size > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
            return;
        }

        string downloadUrl = GetString(asset, "browser_download_url");
        if (downloadUrl.Length == 0 || !Uri.TryCreate(downloadUrl, UriKind.Absolute, out Uri? uri))
        {
            options.WarningSink?.Invoke($"skipping Gitea release asset {displayPath} because the release API did not return a browser download URL");
            return;
        }

        byte[]? bytes = await DownloadReleaseAssetAsync(options, uri, displayPath, cancellationToken).ConfigureAwait(false);
        if (bytes is not null)
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
        }
    }

    private static void AddSyntheticTextFile(
        GiteaSourceOptions options,
        string displayPath,
        string content,
        List<SourceFile> sourceFiles)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        if (bytes.LongLength > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
            return;
        }

        sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, bytes));
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

    private async Task<byte[]?> DownloadGenericPackageFileAsync(
        GiteaGenericPackageSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options.WarningSink, response, $"skipping Gitea package file {displayPath}");
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

    private async Task<byte[]?> DownloadReleaseAssetAsync(
        GiteaSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (!IsAllowedReleaseAssetUri(options, uri))
        {
            options.WarningSink?.Invoke($"skipping Gitea release asset {displayPath} because the asset URL is not an allowed Gitea asset endpoint");
            return null;
        }

        using HttpResponseMessage response = await SendUnauthenticatedRawAsync(uri, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedReleaseAssetUri(options, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping Gitea release asset {displayPath} because the redirected download URL is not an allowed Gitea asset endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping Gitea release asset {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, options, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Gitea release asset {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsAllowedReleaseAssetUri(GiteaSourceOptions options, Uri uri)
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

        return uri.Host.Equals(options.Endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith(string.Concat(".", options.Endpoint.Host), StringComparison.OrdinalIgnoreCase);
    }

    private static void AddContentOrArchiveEntries(
        GiteaGenericPackageSourceOptions options,
        string displayPath,
        byte[] content,
        List<SourceFile> sourceFiles)
    {
        if (!ArchiveReader.IsArchiveContent(content))
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            return;
        }

        if (options.MaxArchiveDepth == 0)
        {
            options.WarningSink?.Invoke($"skipping Gitea package archive {displayPath} because archive traversal is disabled");
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
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            return;
        }

        for (int i = 0; i < entries.Count; i++)
        {
            ArchiveEntry entry = entries[i];
            sourceFiles.Add(new SourceFile(s_remoteFullPath, entry.DisplayPath, entry.Content));
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        GiteaSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(options.Credential, uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        GiteaGenericPackageSourceOptions options,
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
                request.Headers.TryAddWithoutValidation("Authorization", string.Concat("token ", credential));
                return request;
            },
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendUnauthenticatedRawAsync(Uri uri, CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("picket", "dev"));
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
        return await ReadContentWithinLimitAsync(response, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        GiteaGenericPackageSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
        return await ReadContentWithinLimitAsync(response, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        long maxFileBytes,
        Action<string>? warningSink,
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
                if (projectedLength > maxFileBytes)
                {
                    warningSink?.Invoke($"Gitea file byte limit skipped {displayPath}");
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

    private static Uri CreatePullRequestUri(GiteaSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "pulls", options.PullRequestId.ToString(CultureInfo.InvariantCulture)],
            []);
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

    private static Uri CreateGenericPackageFileUri(GiteaGenericPackageSourceOptions options)
    {
        var builder = new UriBuilder(options.Endpoint)
        {
            Path = CreateGenericPackageFilePath(options),
        };
        return builder.Uri;
    }

    private static string CreateGenericPackageFilePath(GiteaGenericPackageSourceOptions options)
    {
        string basePath = options.Endpoint.AbsolutePath.TrimEnd('/');
        const string ApiV1Suffix = "/api/v1";
        if (basePath.EndsWith(ApiV1Suffix, StringComparison.OrdinalIgnoreCase))
        {
            basePath = basePath[..^ApiV1Suffix.Length];
        }

        return CombinePath(
            basePath,
            ["api", "packages", options.Owner, "generic", options.PackageName, options.PackageVersion, options.FileName],
            itemPath: null);
    }

    private static Uri CreateOrganizationRepositoryListUri(GiteaOrganizationSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["orgs", options.Organization, "repos"],
            [
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("limit", RepositoriesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateUserRepositoryListUri(GiteaUserSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["users", options.UserName, "repos"],
            [
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("limit", RepositoriesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateReleaseListUri(GiteaSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "releases"],
            [
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("limit", ReleasesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateReleaseAssetListUri(GiteaSourceOptions options, long releaseId)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "releases", releaseId.ToString(CultureInfo.InvariantCulture), "assets"],
            []);
    }

    private static Uri CreateRepositoryIssueListUri(GiteaSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "issues"],
            [
                new KeyValuePair<string, string>("state", options.IssueState),
                new KeyValuePair<string, string>("type", "issues"),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("limit", IssuesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateRepositoryIssueCommentListUri(GiteaSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repos", options.Owner, options.Name, "issues", "comments"],
            [
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("limit", IssuesPerPage.ToString(CultureInfo.InvariantCulture)),
            ]);
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
        WarnUnsuccessfulResponse(options.WarningSink, response, target);
    }

    private static void WarnUnsuccessfulResponse(
        Action<string>? warningSink,
        HttpResponseMessage response,
        string target)
    {
        warningSink?.Invoke(string.Concat(
            target,
            " because Gitea returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        return response.StatusCode is HttpStatusCode.Moved
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
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

    private static bool HasNextListPage(
        HttpResponseMessage response,
        int page,
        int itemCount,
        int pageSize,
        Action<string>? warningSink,
        string target)
    {
        if (response.Headers.TryGetValues("Link", out IEnumerable<string>? values)
            && values.Any(value => value.Contains("rel=\"next\"", StringComparison.OrdinalIgnoreCase)))
        {
            return HasNextPageWithinLimit(page, warningSink, target);
        }

        if (itemCount < pageSize)
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

    private static bool TryGetJsonInt32(JsonElement value, string propertyName, out int propertyValue)
    {
        propertyValue = 0;
        if (!TryGetJsonInt64(value, propertyName, out long longValue)
            || longValue is < int.MinValue or > int.MaxValue)
        {
            return false;
        }

        propertyValue = (int)longValue;
        return true;
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

    private static bool TryGetIssueNumber(JsonElement comment, out int issueNumber)
    {
        issueNumber = 0;
        string issueUrl = GetString(comment, "issue_url");
        if (issueUrl.Length == 0)
        {
            return false;
        }

        int separator = issueUrl.LastIndexOf('/');
        return separator >= 0
            && separator + 1 < issueUrl.Length
            && int.TryParse(issueUrl.AsSpan(separator + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out issueNumber);
    }

    private static bool TryCreateRepositoryIdentifier(JsonElement repository, string fallbackOwner, out string repositoryIdentifier)
    {
        repositoryIdentifier = GetString(repository, "full_name");
        if (repositoryIdentifier.Length != 0)
        {
            return true;
        }

        string name = GetString(repository, "name");
        if (name.Length == 0)
        {
            return false;
        }

        string owner = GetNestedString(repository, "owner", "login");
        if (owner.Length == 0)
        {
            owner = GetNestedString(repository, "owner", "username");
        }

        if (owner.Length == 0)
        {
            owner = fallbackOwner;
        }

        repositoryIdentifier = string.Concat(owner, "/", name);
        return true;
    }

    private static string CreateDisplayPath(GiteaSourceOptions options, string itemPath)
    {
        return string.Concat(
            "gitea/",
            NormalizeRemoteItemPath(options.Repository),
            "/",
            NormalizeRemoteItemPath(itemPath));
    }

    private static string CreateGenericPackageFileDisplayPath(GiteaGenericPackageSourceOptions options)
    {
        return string.Concat(
            "gitea-package/",
            NormalizeRemoteItemPath(options.Owner),
            "/",
            NormalizeRemoteItemPath(options.PackageName),
            "/",
            NormalizeRemoteItemPath(options.PackageVersion),
            "/",
            NormalizeRemoteItemPath(options.FileName));
    }

    private static string CreateIssueDisplayPath(GiteaSourceOptions options, int issueNumber)
    {
        return string.Concat(
            "gitea/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.Name),
            "/issues/",
            issueNumber.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateIssueCommentDisplayPath(GiteaSourceOptions options, int issueNumber, long commentId)
    {
        return string.Concat(
            "gitea/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.Name),
            "/issues/",
            issueNumber.ToString(CultureInfo.InvariantCulture),
            "/comments/",
            commentId.ToString(CultureInfo.InvariantCulture),
            ".md");
    }

    private static string CreateReleaseDisplayPath(GiteaSourceOptions options, string releaseTag)
    {
        return string.Concat(
            "gitea/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.Name),
            "/releases/",
            EscapeDisplaySegment(releaseTag),
            ".md");
    }

    private static string CreateReleaseAssetDisplayPath(GiteaSourceOptions options, string releaseTag, string assetName)
    {
        return string.Concat(
            "gitea/",
            EscapeDisplaySegment(options.Owner),
            "/",
            EscapeDisplaySegment(options.Name),
            "/releases/",
            EscapeDisplaySegment(releaseTag),
            "/assets/",
            EscapeDisplaySegment(assetName));
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

    private static bool IsCancellationRequested(GiteaOrganizationSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static bool IsCancellationRequested(GiteaUserSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static bool IsCancellationRequested(GiteaGenericPackageSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
