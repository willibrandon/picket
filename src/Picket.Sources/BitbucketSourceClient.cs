using System.Buffers;
using System.Globalization;
using System.Net;
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
    private const int DownloadArtifactsPerPage = 100;
    private const int PipelineStepsPerPage = 100;
    private const int SnippetsPerPage = 100;
    private const int WorkspaceRepositoriesPerPage = 100;
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
            if (options.IncludeDownloads)
            {
                await AddDownloadArtifactsAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludePipelineLogs)
            {
                await AddPipelineStepLogsAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    /// <summary>
    /// Enumerates Bitbucket repository files from all repositories in the selected workspace.
    /// </summary>
    /// <param name="options">The Bitbucket workspace source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateWorkspaceRepositoryFilesAsync(
        BitbucketWorkspaceSourceOptions options,
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
            if (options.ProjectKey.Length != 0
                && !await ValidateWorkspaceProjectAsync(options, cancellationToken).ConfigureAwait(false))
            {
                return sourceFiles;
            }

            await AddWorkspaceRepositoriesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (options.IncludeSnippets)
            {
                await AddWorkspaceSnippetsAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task<bool> ValidateWorkspaceProjectAsync(
        BitbucketWorkspaceSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri projectUri = CreateWorkspaceProjectUri(options);
        using HttpResponseMessage response = await SendAsync(options, projectUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            return true;
        }

        WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket project {options.ProjectKey} in workspace {options.Workspace}");
        return false;
    }

    private async Task AddWorkspaceRepositoriesAsync(
        BitbucketWorkspaceSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri repositoriesUri = CreateWorkspaceRepositoriesUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, repositoriesUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket workspace {options.Workspace}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddWorkspaceRepositoryEntriesAsync(options, root, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextPage(root, page, entryCount, options.WarningSink, $"Bitbucket workspace {options.Workspace} repository enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddWorkspaceRepositoryEntriesAsync(
        BitbucketWorkspaceSourceOptions options,
        JsonElement root,
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

            string repository = GetString(item, "full_name");
            if (repository.Length == 0)
            {
                string slug = GetString(item, "slug");
                if (slug.Length == 0)
                {
                    slug = GetString(item, "name");
                }

                repository = slug.Length == 0 ? string.Empty : string.Concat(options.Workspace, "/", slug);
            }

            if (repository.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket workspace {options.Workspace} repository because Bitbucket did not return a repository name");
                continue;
            }

            BitbucketSourceOptions repositoryOptions;
            try
            {
                repositoryOptions = options.CreateRepositoryOptions(repository);
            }
            catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket workspace {options.Workspace} repository {repository} because it was invalid: {ex.Message}");
                continue;
            }

            List<SourceFile> repositoryFiles = await EnumerateRepositoryFilesAsync(repositoryOptions, cancellationToken).ConfigureAwait(false);
            sourceFiles.AddRange(repositoryFiles);
        }

        return entryCount;
    }

    private async Task AddWorkspaceSnippetsAsync(
        BitbucketWorkspaceSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri snippetsUri = CreateWorkspaceSnippetsUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, snippetsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket snippets in workspace {options.Workspace}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddWorkspaceSnippetEntriesAsync(options, root, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextPage(root, page, entryCount, options.WarningSink, $"Bitbucket snippets workspace {options.Workspace} enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddWorkspaceSnippetEntriesAsync(
        BitbucketWorkspaceSourceOptions options,
        JsonElement root,
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

            string snippetId = GetSnippetId(item);
            if (snippetId.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket snippet in workspace {options.Workspace} because Bitbucket did not return an ID");
                continue;
            }

            await AddSnippetFilesAsync(options, snippetId, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        return entryCount;
    }

    private async Task AddSnippetFilesAsync(
        BitbucketWorkspaceSourceOptions options,
        string snippetId,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri snippetUri = CreateSnippetUri(options, snippetId);
        using HttpResponseMessage response = await SendAsync(options, snippetUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket snippet {CreateSnippetDisplayPath(options, snippetId, string.Empty)}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("files", out JsonElement files) || files.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (JsonProperty file in files.EnumerateObject())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            string normalizedPath = NormalizeRepositoryItemPath(file.Name);
            if (normalizedPath.Length == 0)
            {
                continue;
            }

            string displayPath = CreateSnippetDisplayPath(options, snippetId, normalizedPath);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            Uri rawFileUri = CreateSnippetFileUri(options, snippetId, normalizedPath);
            byte[]? content = await DownloadSnippetFileAsync(options, rawFileUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
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

    private async Task AddDownloadArtifactsAsync(
        BitbucketSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri downloadsUri = CreateDownloadsUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, downloadsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket downloads in repository {options.Repository}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddDownloadArtifactEntriesAsync(options, root, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextPage(root, page, entryCount, options.WarningSink, $"Bitbucket downloads {CreateDisplayPath(options, string.Empty)} enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddDownloadArtifactEntriesAsync(
        BitbucketSourceOptions options,
        JsonElement root,
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

            if (!TryGetJsonString(item, "name", out string name))
            {
                continue;
            }

            string normalizedName = NormalizeRepositoryItemPath(name);
            if (normalizedName.Length == 0)
            {
                continue;
            }

            string displayPath = CreateDownloadDisplayPath(options, normalizedName);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (TryGetJsonInt64(item, "size", out long artifactSize)
                && artifactSize > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
                continue;
            }

            Uri downloadUri = CreateDownloadArtifactUri(options, normalizedName);
            byte[]? content = await DownloadDownloadArtifactAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
            }
        }

        return entryCount;
    }

    private async Task AddPipelineStepLogsAsync(
        BitbucketSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        while (!IsCancellationRequested(options))
        {
            Uri stepsUri = CreatePipelineStepsUri(options, page);
            using HttpResponseMessage response = await SendAsync(options, stepsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket pipeline {options.PipelineId} steps in repository {options.Repository}");
                return;
            }

            using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Bitbucket source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            int entryCount = await AddPipelineStepLogEntriesAsync(options, root, sourceFiles, cancellationToken).ConfigureAwait(false);
            if (!HasNextPage(root, page, entryCount, options.WarningSink, $"Bitbucket pipeline {options.PipelineId} step enumeration"))
            {
                return;
            }

            page++;
        }
    }

    private async Task<int> AddPipelineStepLogEntriesAsync(
        BitbucketSourceOptions options,
        JsonElement root,
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

            string stepId = GetString(item, "uuid");
            if (stepId.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Bitbucket pipeline {options.PipelineId} step log in repository {options.Repository} because Bitbucket did not return a step UUID");
                continue;
            }

            string displayPath = CreatePipelineStepLogDisplayPath(options, stepId);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            Uri logUri = CreatePipelineStepLogUri(options, stepId);
            byte[]? content = await DownloadPipelineStepLogAsync(options, logUri, displayPath, cancellationToken).ConfigureAwait(false);
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
        return await DownloadRawContentAsync(options, uri, displayPath, "Bitbucket file", cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadDownloadArtifactAsync(
        BitbucketSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        return await DownloadRawContentAsync(options, uri, displayPath, "Bitbucket download artifact", cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadPipelineStepLogAsync(
        BitbucketSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        return await DownloadRawContentAsync(options, uri, displayPath, "Bitbucket pipeline log", cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadSnippetFileAsync(
        BitbucketWorkspaceSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedAuthenticatedApiRedirectUri(options.Endpoint, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping Bitbucket snippet file {displayPath} because the redirected file URL is not an allowed Bitbucket API endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendAsync(options, redirectUri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping Bitbucket snippet file {displayPath}");
                return null;
            }

            if (redirectedResponse.Content.Headers.ContentLength.HasValue
                && redirectedResponse.Content.Headers.ContentLength.Value > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Bitbucket snippet file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadRawContentAsync(
        BitbucketSourceOptions options,
        Uri uri,
        string displayPath,
        string target,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: true, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedDownloadRedirectUri(options.Endpoint, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping {target} {displayPath} because the redirected download URL is not an allowed Bitbucket endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping {target} {displayPath}");
                return null;
            }

            if (redirectedResponse.Content.Headers.ContentLength.HasValue
                && redirectedResponse.Content.Headers.ContentLength.Value > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping {target} {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options.MaxFileBytes, options.WarningSink, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static void AddContentOrArchiveEntries(
        BitbucketSourceOptions options,
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
            options.WarningSink?.Invoke($"skipping Bitbucket archive {displayPath} because archive traversal is disabled");
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
        BitbucketSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(CreateAuthorizationHeader(options.CredentialKind, options.Username, options.Credential), uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        BitbucketWorkspaceSourceOptions options,
        Uri uri,
        bool acceptRaw,
        CancellationToken cancellationToken)
    {
        return await SendAsync(CreateAuthorizationHeader(options.CredentialKind, options.Username, options.Credential), uri, acceptRaw, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        AuthenticationHeaderValue authorization,
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
                request.Headers.Authorization = authorization;
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
                    warningSink?.Invoke($"Bitbucket file byte limit skipped {displayPath}");
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

    private static AuthenticationHeaderValue CreateAuthorizationHeader(
        BitbucketCredentialKind credentialKind,
        string username,
        string credential)
    {
        return credentialKind switch
        {
            BitbucketCredentialKind.BearerToken => new AuthenticationHeaderValue("Bearer", credential),
            BitbucketCredentialKind.AppPassword => new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(username, ":", credential)))),
            _ => throw new ArgumentOutOfRangeException(nameof(credentialKind), credentialKind, "Unsupported Bitbucket token kind."),
        };
    }

    private static Uri CreateWorkspaceRepositoriesUri(BitbucketWorkspaceSourceOptions options, int page)
    {
        var query = new List<KeyValuePair<string, string>>(3)
        {
            new("pagelen", WorkspaceRepositoriesPerPage.ToString(CultureInfo.InvariantCulture)),
            new("page", page.ToString(CultureInfo.InvariantCulture)),
        };

        if (options.ProjectKey.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("q", string.Concat("project.key=\"", options.ProjectKey, "\"")));
        }

        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace],
            itemPath: null,
            trailingSlash: false,
            query);
    }

    private static Uri CreateWorkspaceProjectUri(BitbucketWorkspaceSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            ["workspaces", options.Workspace, "projects", options.ProjectKey],
            itemPath: null,
            trailingSlash: false,
            query: []);
    }

    private static Uri CreateWorkspaceSnippetsUri(BitbucketWorkspaceSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["snippets", options.Workspace],
            itemPath: null,
            trailingSlash: false,
            query:
            [
                new KeyValuePair<string, string>("pagelen", SnippetsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateSnippetUri(BitbucketWorkspaceSourceOptions options, string snippetId)
    {
        return CreateUri(
            options.Endpoint,
            ["snippets", options.Workspace, snippetId],
            itemPath: null,
            trailingSlash: false,
            query: []);
    }

    private static Uri CreateSnippetFileUri(BitbucketWorkspaceSourceOptions options, string snippetId, string filePath)
    {
        return CreateUri(
            options.Endpoint,
            ["snippets", options.Workspace, snippetId, "files"],
            filePath,
            trailingSlash: false,
            query: []);
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

    private static Uri CreateDownloadsUri(BitbucketSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "downloads"],
            itemPath: null,
            trailingSlash: false,
            query:
            [
                new KeyValuePair<string, string>("pagelen", DownloadArtifactsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateDownloadArtifactUri(BitbucketSourceOptions options, string fileName)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "downloads", fileName],
            itemPath: null,
            trailingSlash: false,
            query: []);
    }

    private static Uri CreatePipelineStepsUri(BitbucketSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "pipelines", options.PipelineId, "steps"],
            itemPath: null,
            trailingSlash: false,
            query:
            [
                new KeyValuePair<string, string>("pagelen", PipelineStepsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreatePipelineStepLogUri(BitbucketSourceOptions options, string stepId)
    {
        return CreateUri(
            options.Endpoint,
            ["repositories", options.Workspace, options.RepositorySlug, "pipelines", options.PipelineId, "steps", stepId, "log"],
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
        WarnUnsuccessfulResponse(options.WarningSink, response, target);
    }

    private static void WarnUnsuccessfulResponse(
        BitbucketWorkspaceSourceOptions options,
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

    private static bool IsRedirect(HttpResponseMessage response)
    {
        return response.StatusCode is HttpStatusCode.Moved
            or HttpStatusCode.Redirect
            or HttpStatusCode.RedirectMethod
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
    }

    private static bool IsAllowedDownloadRedirectUri(Uri endpoint, Uri redirectUri)
    {
        return redirectUri.IsAbsoluteUri
            && redirectUri.Scheme is "https" or "http"
            && string.IsNullOrEmpty(redirectUri.UserInfo)
            && (endpoint.Scheme == "http" || redirectUri.Scheme == "https");
    }

    private static bool IsAllowedAuthenticatedApiRedirectUri(Uri endpoint, Uri redirectUri)
    {
        return redirectUri.IsAbsoluteUri
            && redirectUri.Scheme.Equals(endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
            && redirectUri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase)
            && redirectUri.Port == endpoint.Port
            && string.IsNullOrEmpty(redirectUri.UserInfo)
            && redirectUri.AbsolutePath.StartsWith(endpoint.AbsolutePath.TrimEnd('/') + "/", StringComparison.Ordinal);
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

    private static string GetSnippetId(JsonElement value)
    {
        if (!value.TryGetProperty("id", out JsonElement property))
        {
            return string.Empty;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString() ?? string.Empty,
            JsonValueKind.Number when property.TryGetInt64(out long id) => id.ToString(CultureInfo.InvariantCulture),
            _ => string.Empty,
        };
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

    private static string CreateDownloadDisplayPath(BitbucketSourceOptions options, string name)
    {
        return string.Concat(
            "bitbucket/",
            NormalizeRemoteItemPath(options.Repository),
            "/downloads/",
            NormalizeRemoteItemPath(name));
    }

    private static string CreatePipelineStepLogDisplayPath(BitbucketSourceOptions options, string stepId)
    {
        return string.Concat(
            "bitbucket/",
            NormalizeRemoteItemPath(options.Repository),
            "/pipelines/",
            NormalizeRemoteItemPath(options.PipelineId),
            "/steps/",
            NormalizeRemoteItemPath(stepId),
            ".log");
    }

    private static string CreateSnippetDisplayPath(BitbucketWorkspaceSourceOptions options, string snippetId, string filePath)
    {
        string normalizedPath = NormalizeRemoteItemPath(filePath);
        string basePath = string.Concat(
            "bitbucket/",
            NormalizeRemoteItemPath(options.Workspace),
            "/snippets/",
            NormalizeRemoteItemPath(snippetId));
        return normalizedPath.Length == 0
            ? basePath
            : string.Concat(basePath, "/", normalizedPath);
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

    private static bool IsCancellationRequested(BitbucketWorkspaceSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
