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
    private const int JobsPerPage = 100;
    private const int PackageFilesPerPage = 100;
    private const int PackagesPerPage = 100;
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

            if ((options.IncludeJobArtifacts || options.IncludeJobLogs) && !IsCancellationRequested(options))
            {
                await AddProjectJobFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludePackages && !IsCancellationRequested(options))
            {
                await AddProjectPackageFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
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
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping GitLab merge request {options.MergeRequestIid.ToString(CultureInfo.InvariantCulture)} in project {options.Project}");
            return (false, options, string.Empty);
        }

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
            maxArchiveDepth: options.MaxArchiveDepth,
            maxArchiveEntries: options.MaxArchiveEntries,
            maxArchiveBytes: options.MaxArchiveBytes,
            maxArchiveCompressionRatio: options.MaxArchiveCompressionRatio,
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
                includeJobArtifacts: options.IncludeJobArtifacts,
                includeJobLogs: options.IncludeJobLogs,
                maxFileBytes: options.MaxFileBytes,
                maxArchiveDepth: options.MaxArchiveDepth,
                maxArchiveEntries: options.MaxArchiveEntries,
                maxArchiveBytes: options.MaxArchiveBytes,
                maxArchiveCompressionRatio: options.MaxArchiveCompressionRatio,
                isPathAllowed: options.IsPathAllowed,
                warningSink: options.WarningSink,
                isCancellationRequested: options.IsCancellationRequested,
                includePackages: options.IncludePackages);
            try
            {
                List<SourceFile> projectFiles = await EnumerateRepositoryFilesAsync(projectOptions, cancellationToken).ConfigureAwait(false);
                sourceFiles.AddRange(projectFiles);
            }
            catch (HttpRequestException)
            {
                options.WarningSink?.Invoke($"skipping GitLab project {project} because a GitLab request failed");
            }
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

    private async Task AddProjectJobFilesAsync(
        GitLabSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri jobsUri = CreateJobsUri(options, page);
            using HttpResponseMessage jobsResponse = await SendAsync(options, jobsUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!jobsResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, jobsResponse, CreateJobsWarningTarget(options));
                return;
            }

            await AddJobFilesAsync(options, jobsResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(jobsResponse, page, options.WarningSink, CreateJobsEnumerationTarget(options));
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddJobFilesAsync(
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

            if (!TryGetJsonInt64(item, "id", out long jobId) || jobId <= 0)
            {
                continue;
            }

            string jobName = GetString(item, "name");
            if (options.IncludeJobLogs)
            {
                await AddJobLogFileAsync(options, jobId, jobName, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeJobArtifacts
                && TryGetJobArtifact(item, out string artifactFileName, out long? artifactSize))
            {
                await AddJobArtifactFilesAsync(
                    options,
                    jobId,
                    artifactFileName,
                    artifactSize,
                    sourceFiles,
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task AddJobLogFileAsync(
        GitLabSourceOptions options,
        long jobId,
        string jobName,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string displayPath = CreateJobLogDisplayPath(options, jobId, jobName);
        if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
        {
            return;
        }

        Uri traceUri = CreateJobTraceUri(options, jobId);
        byte[]? content = await DownloadRawContentAsync(options, traceUri, displayPath, "GitLab job log", cancellationToken).ConfigureAwait(false);
        if (content is not null)
        {
            sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
        }
    }

    private async Task AddJobArtifactFilesAsync(
        GitLabSourceOptions options,
        long jobId,
        string artifactFileName,
        long? artifactSize,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string displayPath = CreateJobArtifactDisplayPath(options, jobId, artifactFileName);
        if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
        {
            return;
        }

        if (artifactSize.HasValue && artifactSize.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
            return;
        }

        Uri artifactUri = CreateJobArtifactUri(options, jobId);
        byte[]? content = await DownloadRawContentAsync(options, artifactUri, displayPath, "GitLab job artifact", cancellationToken).ConfigureAwait(false);
        if (content is not null)
        {
            AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
        }
    }

    private async Task AddProjectPackageFilesAsync(
        GitLabSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri packagesUri = CreatePackagesUri(options, page);
            using HttpResponseMessage packagesResponse = await SendAsync(options, packagesUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!packagesResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, packagesResponse, $"skipping GitLab project {options.Project} generic packages");
                return;
            }

            await AddPackageFilesAsync(options, packagesResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(packagesResponse, page, options.WarningSink, $"GitLab project {options.Project} generic package enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddPackageFilesAsync(
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

            if (!TryGetJsonInt64(item, "id", out long packageId)
                || packageId <= 0
                || !GetString(item, "package_type").Equals("generic", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string packageName = GetString(item, "name");
            string packageVersion = GetString(item, "version");
            if (packageName.Length == 0 || packageVersion.Length == 0)
            {
                continue;
            }

            await AddPackageFileEntriesAsync(options, packageId, packageName, packageVersion, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddPackageFileEntriesAsync(
        GitLabSourceOptions options,
        long packageId,
        string packageName,
        string packageVersion,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        int page = 1;
        bool hasNextPage;
        do
        {
            Uri packageFilesUri = CreatePackageFilesUri(options, packageId, page);
            using HttpResponseMessage packageFilesResponse = await SendAsync(options, packageFilesUri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
            if (!packageFilesResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, packageFilesResponse, $"skipping GitLab package {packageName} {packageVersion} files");
                return;
            }

            await AddGenericPackageFileEntriesAsync(options, packageName, packageVersion, packageFilesResponse, sourceFiles, cancellationToken).ConfigureAwait(false);
            hasNextPage = HasNextPage(packageFilesResponse, page, options.WarningSink, $"GitLab package {packageName} {packageVersion} file enumeration");
            page++;
        }
        while (hasNextPage && !IsCancellationRequested(options));
    }

    private async Task AddGenericPackageFileEntriesAsync(
        GitLabSourceOptions options,
        string packageName,
        string packageVersion,
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

            string fileName = GetString(item, "file_name");
            if (fileName.Length == 0)
            {
                continue;
            }

            string displayPath = CreatePackageFileDisplayPath(options, packageName, packageVersion, fileName);
            if (options.IsPathAllowed is not null && options.IsPathAllowed(displayPath))
            {
                continue;
            }

            if (TryGetJsonInt64(item, "size", out long fileSize)
                && fileSize > options.MaxFileBytes)
            {
                options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
                continue;
            }

            Uri fileUri = CreateGenericPackageFileUri(options, packageName, packageVersion, fileName);
            byte[]? content = await DownloadRawContentAsync(options, fileUri, displayPath, "GitLab package file", cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
            }
        }
    }

    private async Task<string> ReadDefaultBranchAsync(
        GitLabSourceOptions options,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateProjectUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptRaw: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping GitLab project {options.Project}");
            return string.Empty;
        }

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
        return await DownloadRawContentAsync(options, uri, displayPath, "GitLab file", cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadRawContentAsync(
        GitLabSourceOptions options,
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
                options.WarningSink?.Invoke($"skipping {target} {displayPath} because the redirected download URL is not an allowed GitLab endpoint");
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
                options.WarningSink?.Invoke($"GitLab file byte limit skipped {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, options, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping {target} {displayPath}");
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

    private static void AddContentOrArchiveEntries(
        GitLabSourceOptions options,
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
            options.WarningSink?.Invoke($"skipping GitLab archive {displayPath} because archive traversal is disabled");
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

    private static Uri CreateJobsUri(GitLabSourceOptions options, int page)
    {
        string[] pathSegments = options.PipelineId == 0
            ? ["projects", options.Project, "jobs"]
            : ["projects", options.Project, "pipelines", options.PipelineId.ToString(CultureInfo.InvariantCulture), "jobs"];

        return CreateUri(
            options.Endpoint,
            pathSegments,
            [
                new KeyValuePair<string, string>("per_page", JobsPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreatePackagesUri(GitLabSourceOptions options, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "packages"],
            [
                new KeyValuePair<string, string>("package_type", "generic"),
                new KeyValuePair<string, string>("per_page", PackagesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreatePackageFilesUri(GitLabSourceOptions options, long packageId, int page)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "packages", packageId.ToString(CultureInfo.InvariantCulture), "package_files"],
            [
                new KeyValuePair<string, string>("per_page", PackageFilesPerPage.ToString(CultureInfo.InvariantCulture)),
                new KeyValuePair<string, string>("page", page.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Uri CreateGenericPackageFileUri(
        GitLabSourceOptions options,
        string packageName,
        string packageVersion,
        string fileName)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "packages", "generic", packageName, packageVersion, fileName],
            []);
    }

    private static string CreateJobsWarningTarget(GitLabSourceOptions options)
    {
        return options.PipelineId == 0
            ? $"skipping GitLab project {options.Project} jobs"
            : $"skipping GitLab pipeline {options.PipelineId.ToString(CultureInfo.InvariantCulture)} jobs in project {options.Project}";
    }

    private static string CreateJobsEnumerationTarget(GitLabSourceOptions options)
    {
        return options.PipelineId == 0
            ? $"GitLab project {options.Project} job enumeration"
            : $"GitLab pipeline {options.PipelineId.ToString(CultureInfo.InvariantCulture)} job enumeration in project {options.Project}";
    }

    private static Uri CreateJobArtifactUri(GitLabSourceOptions options, long jobId)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "jobs", jobId.ToString(CultureInfo.InvariantCulture), "artifacts"],
            []);
    }

    private static Uri CreateJobTraceUri(GitLabSourceOptions options, long jobId)
    {
        return CreateUri(
            options.Endpoint,
            ["projects", options.Project, "jobs", jobId.ToString(CultureInfo.InvariantCulture), "trace"],
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

    private static bool TryGetJobArtifact(JsonElement value, out string fileName, out long? size)
    {
        fileName = string.Empty;
        size = null;
        if (!value.TryGetProperty("artifacts_file", out JsonElement artifactsFile)
            || artifactsFile.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        fileName = GetString(artifactsFile, "filename");
        if (fileName.Length == 0)
        {
            return false;
        }

        if (TryGetJsonInt64(artifactsFile, "size", out long artifactSize))
        {
            size = artifactSize;
        }

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

    private static string CreateJobArtifactDisplayPath(GitLabSourceOptions options, long jobId, string fileName)
    {
        return string.Concat(
            "gitlab-job-artifact/",
            NormalizeRemoteItemPath(options.Project),
            "/",
            jobId.ToString(CultureInfo.InvariantCulture),
            "/",
            NormalizeRemoteItemPath(fileName));
    }

    private static string CreateJobLogDisplayPath(GitLabSourceOptions options, long jobId, string jobName)
    {
        string fileName = jobName.Length == 0
            ? string.Concat("job-", jobId.ToString(CultureInfo.InvariantCulture), ".log")
            : string.Concat(jobName, ".log");
        return string.Concat(
            "gitlab-job-log/",
            NormalizeRemoteItemPath(options.Project),
            "/",
            jobId.ToString(CultureInfo.InvariantCulture),
            "-",
            NormalizeRemoteItemPath(fileName));
    }

    private static string CreatePackageFileDisplayPath(
        GitLabSourceOptions options,
        string packageName,
        string packageVersion,
        string fileName)
    {
        return string.Concat(
            "gitlab-package/",
            NormalizeRemoteItemPath(options.Project),
            "/",
            NormalizeRemoteItemPath(packageName),
            "/",
            NormalizeRemoteItemPath(packageVersion),
            "/",
            NormalizeRemoteItemPath(fileName));
    }

    private static bool IsAllowedDownloadRedirectUri(Uri endpoint, Uri redirectUri)
    {
        return redirectUri.IsAbsoluteUri
            && redirectUri.Scheme is "https" or "http"
            && string.IsNullOrEmpty(redirectUri.UserInfo)
            && (endpoint.Scheme == "http" || redirectUri.Scheme == "https");
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        int statusCode = (int)response.StatusCode;
        return statusCode is 301 or 302 or 303 or 307 or 308;
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
