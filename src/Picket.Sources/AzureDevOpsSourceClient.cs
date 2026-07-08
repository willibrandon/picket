using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Enumerates Azure DevOps source files through REST APIs.
/// </summary>
/// <param name="httpClient">The HTTP client used for Azure DevOps requests.</param>
public sealed class AzureDevOpsSourceClient(HttpClient httpClient)
{
    private const string ApiVersion = "7.1";
    private const string ContinuationTokenHeader = "x-ms-continuationtoken";
    private const int MaxContinuationPages = 1000;
    private static readonly string s_remoteFullPath = Path.Combine(Path.GetTempPath(), "picket-azure-devops-remote");
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));

    /// <summary>
    /// Enumerates Azure Repos files selected by the supplied options.
    /// </summary>
    /// <param name="options">The Azure DevOps source options.</param>
    /// <param name="cancellationToken">A token that can cancel source enumeration.</param>
    /// <returns>The selected source files.</returns>
    public async Task<List<SourceFile>> EnumerateRepositoryFilesAsync(
        AzureDevOpsSourceOptions options,
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
            List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)> repositories = await ListRepositoriesAsync(options, cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < repositories.Count; i++)
            {
                if (IsCancellationRequested(options))
                {
                    break;
                }

                (string id, string name, string projectName, string defaultBranch, bool hasDefaultBranchMetadata) = repositories[i];
                if (options.Repository.Length != 0
                    && !name.Equals(options.Repository, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (projectName.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Azure DevOps repository {name} because its project name was not returned");
                    continue;
                }

                if (options.PullRequestId == 0
                    && options.Branch.Length == 0
                    && hasDefaultBranchMetadata
                    && defaultBranch.Length == 0)
                {
                    options.WarningSink?.Invoke($"skipping Azure DevOps repository {name} because it does not have a default branch");
                    continue;
                }

                (bool shouldScan, string scanRepositoryId, string scanRepositoryName, string scanProjectName, string version, string versionType) = await ResolveRepositoryVersionAsync(
                    options,
                    id,
                    name,
                    projectName,
                    cancellationToken).ConfigureAwait(false);
                if (!shouldScan)
                {
                    continue;
                }

                await AddRepositoryFilesAsync(
                    options,
                    scanRepositoryId,
                    scanRepositoryName,
                    scanProjectName,
                    version,
                    versionType,
                    sourceFiles,
                    cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeWikis && !IsCancellationRequested(options))
            {
                await AddWikiFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if ((options.IncludeArtifacts || options.IncludeLogs) && !IsCancellationRequested(options))
            {
                await AddBuildFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }

            if (options.IncludeReleaseArtifacts && !IsCancellationRequested(options))
            {
                await AddReleaseArtifactFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (RemoteMetadataTooLargeException)
        {
            return sourceFiles;
        }

        return sourceFiles;
    }

    private async Task<List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)>> ListRepositoriesAsync(
        AzureDevOpsSourceOptions options,
        CancellationToken cancellationToken)
    {
        var repositories = new List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)>();
        string continuationToken = string.Empty;
        int pageCount = 0;
        do
        {
            pageCount++;
            Uri uri = CreateRepositoryListUri(options, continuationToken);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await AddRepositoriesAsync(options, response, repositories, cancellationToken).ConfigureAwait(false);
            continuationToken = ReadContinuationToken(response);
        }
        while (continuationToken.Length != 0 && pageCount < MaxContinuationPages && !IsCancellationRequested(options));

        if (continuationToken.Length != 0 && pageCount >= MaxContinuationPages)
        {
            options.WarningSink?.Invoke("Azure DevOps repository enumeration stopped at the pagination safety limit");
        }

        return repositories;
    }

    private async Task AddRepositoryFilesAsync(
        AzureDevOpsSourceOptions options,
        string repositoryId,
        string repositoryName,
        string projectName,
        string version,
        string versionType,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string continuationToken = string.Empty;
        int pageCount = 0;
        do
        {
            pageCount++;
            Uri uri = CreateItemListUri(options, projectName, repositoryId, version, versionType, continuationToken);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps repository {repositoryName}");
                return;
            }

            await AddItemFilesAsync(options, response, repositoryId, repositoryName, projectName, version, versionType, sourceFiles, cancellationToken).ConfigureAwait(false);
            continuationToken = ReadContinuationToken(response);
        }
        while (continuationToken.Length != 0 && pageCount < MaxContinuationPages && !IsCancellationRequested(options));

        if (continuationToken.Length != 0 && pageCount >= MaxContinuationPages)
        {
            options.WarningSink?.Invoke($"Azure DevOps repository {repositoryName} item enumeration stopped at the pagination safety limit");
        }
    }

    private async Task<(bool ShouldScan, string RepositoryId, string RepositoryName, string ProjectName, string Version, string VersionType)> ResolveRepositoryVersionAsync(
        AzureDevOpsSourceOptions options,
        string repositoryId,
        string repositoryName,
        string projectName,
        CancellationToken cancellationToken)
    {
        if (options.PullRequestId == 0)
        {
            return (true, repositoryId, repositoryName, projectName, options.Branch, options.Branch.Length == 0 ? string.Empty : "branch");
        }

        Uri uri = CreatePullRequestUri(options, projectName, repositoryId);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {repositoryName}");
            return (false, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        (string scanRepositoryId, string scanRepositoryName, string scanProjectName) = ResolvePullRequestSourceRepository(
            document.RootElement,
            repositoryId,
            repositoryName,
            projectName);
        string sourceCommitId = GetNestedString(document.RootElement, "lastMergeSourceCommit", "commitId");
        if (sourceCommitId.Length != 0)
        {
            return (true, scanRepositoryId, scanRepositoryName, scanProjectName, sourceCommitId, "commit");
        }

        string sourceRefName = NormalizeSourceRefName(GetString(document.RootElement, "sourceRefName"));
        if (sourceRefName.Length != 0)
        {
            return (true, scanRepositoryId, scanRepositoryName, scanProjectName, sourceRefName, "branch");
        }

        options.WarningSink?.Invoke(
            $"skipping Azure DevOps pull request {options.PullRequestId.ToString(CultureInfo.InvariantCulture)} in repository {repositoryName} because its source head was not returned");
        return (false, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
    }

    private async Task AddWikiFilesAsync(
        AzureDevOpsSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        List<(string Name, string ProjectName, string RepositoryId, string MappedPath, string Version, bool IsDisabled)> wikis = await ListWikisAsync(options, cancellationToken).ConfigureAwait(false);
        for (int i = 0; i < wikis.Count; i++)
        {
            if (IsCancellationRequested(options))
            {
                break;
            }

            (string name, string projectName, string repositoryId, string mappedPath, string version, bool isDisabled) = wikis[i];
            if (isDisabled)
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps wiki {name} because it is disabled");
                continue;
            }

            if (projectName.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps wiki {name} because its project was not returned");
                continue;
            }

            if (repositoryId.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps wiki {name} because its backing repository was not returned");
                continue;
            }

            string itemVersion = options.Branch.Length == 0 ? version : options.Branch;
            if (itemVersion.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps wiki {name} because it does not have a version");
                continue;
            }

            await AddWikiRepositoryFilesAsync(
                options,
                projectName,
                name,
                repositoryId,
                mappedPath,
                itemVersion,
                sourceFiles,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddBuildFilesAsync(
        AzureDevOpsSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (options.IncludeArtifacts)
        {
            await AddBuildArtifactFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeLogs && !IsCancellationRequested(options))
        {
            await AddBuildLogFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddBuildArtifactFilesAsync(
        AzureDevOpsSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateBuildArtifactListUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps build artifacts for build {options.BuildId.ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!TryGetJsonArray(document.RootElement, out JsonElement artifacts))
        {
            return;
        }

        foreach (JsonElement artifact in artifacts.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            await AddBuildArtifactFileAsync(options, artifact, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddBuildArtifactFileAsync(
        AzureDevOpsSourceOptions options,
        JsonElement artifact,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string artifactName = GetString(artifact, "name");
        if (artifactName.Length == 0)
        {
            artifactName = TryGetJsonInt32(artifact, "id", out int artifactId)
                ? artifactId.ToString(CultureInfo.InvariantCulture)
                : "artifact";
        }

        string displayPath = CreateBuildArtifactDisplayPath(options, artifactName);
        await AddArtifactContentAsync(options, artifact, displayPath, "artifact", sourceFiles, cancellationToken).ConfigureAwait(false);
    }

    private async Task AddArtifactContentAsync(
        AzureDevOpsSourceOptions options,
        JsonElement artifact,
        string displayPath,
        string limitName,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (!artifact.TryGetProperty("resource", out JsonElement resource)
            || resource.ValueKind != JsonValueKind.Object
            || !TryGetJsonString(resource, "downloadUrl", out string downloadUrl)
            || !Uri.TryCreate(downloadUrl, UriKind.Absolute, out Uri? downloadUri))
        {
            options.WarningSink?.Invoke($"skipping Azure DevOps {limitName} {displayPath} because the artifact API did not return a download URL");
            return;
        }

        byte[]? content = await DownloadBuildContentAsync(
            options,
            downloadUri,
            displayPath,
            options.MaxArtifactBytes,
            limitName,
            cancellationToken).ConfigureAwait(false);
        if (content is null)
        {
            return;
        }

        AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
    }

    private async Task AddBuildLogFilesAsync(
        AzureDevOpsSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateBuildLogListUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps build logs for build {options.BuildId.ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!TryGetJsonArray(document.RootElement, out JsonElement logs))
        {
            return;
        }

        foreach (JsonElement log in logs.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            await AddBuildLogFileAsync(options, log, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddReleaseArtifactFilesAsync(
        AzureDevOpsSourceOptions options,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        Uri uri = CreateReleaseUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping Azure DevOps release artifacts for release {options.ReleaseId.ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
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

            await AddReleaseArtifactFileAsync(options, artifact, sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddReleaseArtifactFileAsync(
        AzureDevOpsSourceOptions options,
        JsonElement releaseArtifact,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string alias = GetString(releaseArtifact, "alias");
        if (alias.Length == 0)
        {
            alias = "artifact";
        }

        string artifactType = GetString(releaseArtifact, "type");
        if (!artifactType.Equals("Build", StringComparison.OrdinalIgnoreCase))
        {
            options.WarningSink?.Invoke($"skipping Azure DevOps release artifact {alias} because artifact type {artifactType} is not supported");
            return;
        }

        if (!TryGetReleaseArtifactBuildId(releaseArtifact, out int buildId))
        {
            options.WarningSink?.Invoke($"skipping Azure DevOps release artifact {alias} because it did not include a build version ID");
            return;
        }

        string projectName = GetReleaseArtifactProjectName(options, releaseArtifact);
        Uri uri = CreateBuildArtifactListUri(options, projectName, buildId);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(
                options,
                response,
                $"skipping Azure DevOps release artifact {alias} for release {options.ReleaseId.ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!TryGetJsonArray(document.RootElement, out JsonElement artifacts))
        {
            return;
        }

        foreach (JsonElement buildArtifact in artifacts.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            string buildArtifactName = GetArtifactName(buildArtifact);
            string displayPath = CreateReleaseArtifactDisplayPath(options, alias, buildArtifactName);
            await AddArtifactContentAsync(options, buildArtifact, displayPath, "release artifact", sourceFiles, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task AddBuildLogFileAsync(
        AzureDevOpsSourceOptions options,
        JsonElement log,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        if (!TryGetJsonInt32(log, "id", out int logId))
        {
            return;
        }

        string displayPath = CreateBuildLogDisplayPath(options, logId);
        Uri uri = CreateBuildLogDownloadUri(options, logId);
        byte[]? content = await DownloadBuildContentAsync(
            options,
            uri,
            displayPath,
            options.MaxLogBytes,
            "log",
            cancellationToken).ConfigureAwait(false);
        if (content is null)
        {
            return;
        }

        AddContentOrArchiveEntries(options, displayPath, content, sourceFiles);
    }

    private async Task<List<(string Name, string ProjectName, string RepositoryId, string MappedPath, string Version, bool IsDisabled)>> ListWikisAsync(
        AzureDevOpsSourceOptions options,
        CancellationToken cancellationToken)
    {
        var wikis = new List<(string Name, string ProjectName, string RepositoryId, string MappedPath, string Version, bool IsDisabled)>();
        Uri uri = CreateWikiListUri(options);
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, "skipping Azure DevOps wikis");
            return wikis;
        }

        await AddWikisAsync(options, response, wikis, cancellationToken).ConfigureAwait(false);
        return wikis;
    }

    private async Task AddWikiRepositoryFilesAsync(
        AzureDevOpsSourceOptions options,
        string projectName,
        string wikiName,
        string repositoryId,
        string mappedPath,
        string version,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string continuationToken = string.Empty;
        int pageCount = 0;
        do
        {
            pageCount++;
            Uri uri = CreateWikiItemListUri(options, projectName, repositoryId, mappedPath, version, continuationToken);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps wiki {wikiName}");
                return;
            }

            await AddWikiItemFilesAsync(options, response, projectName, wikiName, repositoryId, version, sourceFiles, cancellationToken).ConfigureAwait(false);
            continuationToken = ReadContinuationToken(response);
        }
        while (continuationToken.Length != 0 && pageCount < MaxContinuationPages && !IsCancellationRequested(options));

        if (continuationToken.Length != 0 && pageCount >= MaxContinuationPages)
        {
            options.WarningSink?.Invoke($"Azure DevOps wiki {wikiName} item enumeration stopped at the pagination safety limit");
        }
    }

    private async Task AddItemFilesAsync(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        string repositoryId,
        string repositoryName,
        string projectName,
        string version,
        string versionType,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in values.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonString(item, "path", out string path)
                || !IsBlobItem(item))
            {
                continue;
            }

            Uri downloadUri = CreateItemDownloadUri(options, projectName, repositoryId, path, version, versionType);
            string displayPath = CreateDisplayPath(projectName, repositoryName, path);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task AddWikiItemFilesAsync(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        string projectName,
        string wikiName,
        string repositoryId,
        string version,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement item in values.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonString(item, "path", out string path)
                || !IsBlobItem(item))
            {
                continue;
            }

            Uri downloadUri = CreateWikiItemDownloadUri(options, projectName, repositoryId, path, version);
            string displayPath = CreateWikiDisplayPath(projectName, wikiName, path);
            byte[]? content = await DownloadFileAsync(options, downloadUri, displayPath, cancellationToken).ConfigureAwait(false);
            if (content is not null)
            {
                sourceFiles.Add(new SourceFile(s_remoteFullPath, displayPath, content));
            }
        }
    }

    private async Task<byte[]?> DownloadFileAsync(
        AzureDevOpsSourceOptions options,
        Uri uri,
        string displayPath,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: false, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps file {displayPath}");
            return null;
        }

        if (response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes)
        {
            options.WarningSink?.Invoke($"Azure DevOps file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]?> DownloadBuildContentAsync(
        AzureDevOpsSourceOptions options,
        Uri uri,
        string displayPath,
        long? maxBytes,
        string limitName,
        CancellationToken cancellationToken)
    {
        if (!IsAllowedAzureDevOpsUri(options.Endpoint, uri))
        {
            options.WarningSink?.Invoke($"skipping Azure DevOps {limitName} {displayPath} because the download URL is not an allowed Azure DevOps endpoint");
            return null;
        }

        using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: false, cancellationToken).ConfigureAwait(false);
        if (IsRedirect(response) && response.Headers.Location is not null)
        {
            Uri redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(uri, response.Headers.Location);
            if (!IsAllowedAzureDevOpsRedirectUri(options.Endpoint, redirectUri))
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps {limitName} {displayPath} because the redirected download URL is not an allowed Azure DevOps artifact endpoint");
                return null;
            }

            using HttpResponseMessage redirectedResponse = await SendUnauthenticatedRawAsync(redirectUri, cancellationToken).ConfigureAwait(false);
            if (!redirectedResponse.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, redirectedResponse, $"skipping Azure DevOps {limitName} {displayPath}");
                return null;
            }

            return await ReadContentWithinLimitAsync(redirectedResponse, maxBytes, options.WarningSink, limitName, displayPath, cancellationToken).ConfigureAwait(false);
        }

        if (!response.IsSuccessStatusCode)
        {
            WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps {limitName} {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, maxBytes, options.WarningSink, limitName, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static void AddContentOrArchiveEntries(
        AzureDevOpsSourceOptions options,
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
            options.WarningSink?.Invoke($"skipping Azure DevOps archive {displayPath} because archive traversal is disabled");
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
        AzureDevOpsSourceOptions options,
        Uri uri,
        bool acceptJson,
        CancellationToken cancellationToken)
    {
        return await SendWithRetryAsync(
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptJson ? "application/json" : "application/octet-stream"));
                request.Headers.Authorization = CreateAuthorizationHeader(options);
                return request;
            },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendUnauthenticatedRawAsync(Uri uri, CancellationToken cancellationToken)
    {
        return await SendWithRetryAsync(
            () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
                return request;
            },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(
        Func<HttpRequestMessage> requestFactory,
        CancellationToken cancellationToken)
    {
        return await RemoteSourceHttpRetry.SendAsync(
            _httpClient,
            requestFactory,
            RemoteSourceHttpRetry.IsGenericRetryableResponse,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task AddRepositoriesAsync(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)> repositories,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement repository in values.EnumerateArray())
        {
            if (!TryGetJsonString(repository, "id", out string id)
                || !TryGetJsonString(repository, "name", out string name))
            {
                continue;
            }

            string projectName = string.Empty;
            if (repository.TryGetProperty("project", out JsonElement project)
                && project.ValueKind == JsonValueKind.Object)
            {
                TryGetJsonString(project, "name", out projectName);
            }

            string defaultBranch = string.Empty;
            bool hasDefaultBranchMetadata = repository.TryGetProperty("defaultBranch", out JsonElement defaultBranchElement);
            if (hasDefaultBranchMetadata && defaultBranchElement.ValueKind == JsonValueKind.String)
            {
                defaultBranch = defaultBranchElement.GetString() ?? string.Empty;
            }

            repositories.Add((id, name, projectName, defaultBranch, hasDefaultBranchMetadata));
        }
    }

    private static async Task AddWikisAsync(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        List<(string Name, string ProjectName, string RepositoryId, string MappedPath, string Version, bool IsDisabled)> wikis,
        CancellationToken cancellationToken)
    {
        using JsonDocument document = await RemoteJsonDocumentReader.ReadAsync(response.Content, "Azure DevOps source metadata", options.WarningSink, cancellationToken).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("value", out JsonElement values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (JsonElement wiki in values.EnumerateArray())
        {
            if (IsCancellationRequested(options))
            {
                return;
            }

            if (!TryGetJsonString(wiki, "name", out string name))
            {
                continue;
            }

            string repositoryId = GetString(wiki, "repositoryId");
            if (repositoryId.Length == 0)
            {
                repositoryId = GetString(wiki, "id");
            }

            string projectName = options.Project.Length == 0 ? GetString(wiki, "projectId") : options.Project;
            wikis.Add((
                name,
                projectName,
                repositoryId,
                NormalizeWikiMappedPath(GetString(wiki, "mappedPath")),
                GetFirstWikiVersion(wiki),
                GetBoolean(wiki, "isDisabled")));
        }
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        AzureDevOpsSourceOptions options,
        string displayPath,
        CancellationToken cancellationToken)
    {
        return await ReadContentWithinLimitAsync(response, options.MaxFileBytes, options.WarningSink, "file", displayPath, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadContentWithinLimitAsync(
        HttpResponseMessage response,
        long? maxBytes,
        Action<string>? warningSink,
        string limitName,
        string displayPath,
        CancellationToken cancellationToken)
    {
        if (maxBytes.HasValue
            && response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > maxBytes.Value)
        {
            warningSink?.Invoke($"Azure DevOps {limitName} byte limit skipped {displayPath}");
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

                if (maxBytes.HasValue)
                {
                    long projectedLength = memory.Length + read;
                    if (projectedLength > maxBytes.Value)
                    {
                        warningSink?.Invoke($"Azure DevOps {limitName} byte limit skipped {displayPath}");
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

    private static void WarnUnsuccessfulResponse(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        string target)
    {
        options.WarningSink?.Invoke(string.Concat(
            target,
            " because Azure DevOps returned ",
            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
            " ",
            response.StatusCode));
    }

    private static AuthenticationHeaderValue CreateAuthorizationHeader(AzureDevOpsSourceOptions options)
    {
        return options.CredentialKind switch
        {
            AzureDevOpsCredentialKind.PersonalAccessToken => new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(":", options.Credential)))),
            AzureDevOpsCredentialKind.BearerToken => new AuthenticationHeaderValue("Bearer", options.Credential),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };
    }

    private static Uri CreateRepositoryListUri(AzureDevOpsSourceOptions options, string continuationToken)
    {
        string[] segments = options.Project.Length == 0
            ? ["_apis", "git", "repositories"]
            : [options.Project, "_apis", "git", "repositories"];
        return CreateUri(options.Endpoint, segments, CreateApiQuery(continuationToken));
    }

    private static Uri CreateWikiListUri(AzureDevOpsSourceOptions options)
    {
        string[] segments = options.Project.Length == 0
            ? ["_apis", "wiki", "wikis"]
            : [options.Project, "_apis", "wiki", "wikis"];
        return CreateUri(options.Endpoint, segments, CreateApiQuery(continuationToken: string.Empty));
    }

    private static Uri CreateItemListUri(
        AzureDevOpsSourceOptions options,
        string projectName,
        string repositoryId,
        string version,
        string versionType,
        string continuationToken)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("recursionLevel", "Full"),
            new("includeContentMetadata", "true")
        };
        AddVersionDescriptorQuery(version, versionType, query);
        AddApiQuery(query, continuationToken);
        return CreateUri(options.Endpoint, [projectName, "_apis", "git", "repositories", repositoryId, "items"], query);
    }

    private static Uri CreatePullRequestUri(
        AzureDevOpsSourceOptions options,
        string projectName,
        string repositoryId)
    {
        return CreateUri(
            options.Endpoint,
            [
                projectName,
                "_apis",
                "git",
                "repositories",
                repositoryId,
                "pullRequests",
                options.PullRequestId.ToString(CultureInfo.InvariantCulture)
            ],
            CreateApiQuery(continuationToken: string.Empty));
    }

    private static Uri CreateWikiItemListUri(
        AzureDevOpsSourceOptions options,
        string projectName,
        string repositoryId,
        string mappedPath,
        string version,
        string continuationToken)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("recursionLevel", "Full"),
            new("includeContentMetadata", "true")
        };
        if (mappedPath.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("scopePath", mappedPath));
        }

        AddBranchQuery(version, query);
        AddApiQuery(query, continuationToken);
        return CreateUri(options.Endpoint, [projectName, "_apis", "git", "repositories", repositoryId, "items"], query);
    }

    private static Uri CreateItemDownloadUri(
        AzureDevOpsSourceOptions options,
        string projectName,
        string repositoryId,
        string path,
        string version,
        string versionType)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("path", path),
            new("download", "true")
        };
        AddVersionDescriptorQuery(version, versionType, query);
        AddApiQuery(query, continuationToken: string.Empty);
        return CreateUri(options.Endpoint, [projectName, "_apis", "git", "repositories", repositoryId, "items"], query);
    }

    private static Uri CreateWikiItemDownloadUri(
        AzureDevOpsSourceOptions options,
        string projectName,
        string repositoryId,
        string path,
        string version)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("path", path),
            new("download", "true")
        };
        AddBranchQuery(version, query);
        AddApiQuery(query, continuationToken: string.Empty);
        return CreateUri(options.Endpoint, [projectName, "_apis", "git", "repositories", repositoryId, "items"], query);
    }

    private static Uri CreateBuildArtifactListUri(AzureDevOpsSourceOptions options)
    {
        return CreateBuildArtifactListUri(options, options.Project, options.BuildId);
    }

    private static Uri CreateBuildArtifactListUri(AzureDevOpsSourceOptions options, string projectName, int buildId)
    {
        return CreateUri(
            options.Endpoint,
            [projectName, "_apis", "build", "builds", buildId.ToString(CultureInfo.InvariantCulture), "artifacts"],
            CreateApiQuery(continuationToken: string.Empty));
    }

    private static Uri CreateReleaseUri(AzureDevOpsSourceOptions options)
    {
        return CreateUri(
            options.ReleaseEndpoint,
            [options.Project, "_apis", "release", "releases", options.ReleaseId.ToString(CultureInfo.InvariantCulture)],
            CreateApiQuery(continuationToken: string.Empty));
    }

    private static Uri CreateBuildLogListUri(AzureDevOpsSourceOptions options)
    {
        return CreateUri(
            options.Endpoint,
            [options.Project, "_apis", "build", "builds", options.BuildId.ToString(CultureInfo.InvariantCulture), "logs"],
            CreateApiQuery(continuationToken: string.Empty));
    }

    private static Uri CreateBuildLogDownloadUri(AzureDevOpsSourceOptions options, int logId)
    {
        return CreateUri(
            options.Endpoint,
            [
                options.Project,
                "_apis",
                "build",
                "builds",
                options.BuildId.ToString(CultureInfo.InvariantCulture),
                "logs",
                logId.ToString(CultureInfo.InvariantCulture)
            ],
            CreateApiQuery(continuationToken: string.Empty));
    }

    private static List<KeyValuePair<string, string>> CreateApiQuery(string continuationToken)
    {
        var query = new List<KeyValuePair<string, string>>();
        AddApiQuery(query, continuationToken);
        return query;
    }

    private static void AddApiQuery(List<KeyValuePair<string, string>> query, string continuationToken)
    {
        query.Add(new KeyValuePair<string, string>("api-version", ApiVersion));
        if (continuationToken.Length != 0)
        {
            query.Add(new KeyValuePair<string, string>("continuationToken", continuationToken));
        }
    }

    private static void AddBranchQuery(string branch, List<KeyValuePair<string, string>> query)
    {
        AddVersionDescriptorQuery(branch, branch.Length == 0 ? string.Empty : "branch", query);
    }

    private static void AddVersionDescriptorQuery(string version, string versionType, List<KeyValuePair<string, string>> query)
    {
        if (version.Length == 0)
        {
            return;
        }

        query.Add(new KeyValuePair<string, string>("versionDescriptor.version", version));
        query.Add(new KeyValuePair<string, string>("versionDescriptor.versionType", versionType));
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

    private static string ReadContinuationToken(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(ContinuationTokenHeader, out IEnumerable<string>? values))
        {
            return string.Empty;
        }

        foreach (string value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static bool IsBlobItem(JsonElement item)
    {
        return TryGetJsonString(item, "gitObjectType", out string gitObjectType)
            && gitObjectType.Equals("blob", StringComparison.OrdinalIgnoreCase);
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

    private static (string RepositoryId, string RepositoryName, string ProjectName) ResolvePullRequestSourceRepository(
        JsonElement pullRequest,
        string repositoryId,
        string repositoryName,
        string projectName)
    {
        if (!pullRequest.TryGetProperty("forkSource", out JsonElement forkSource)
            || forkSource.ValueKind != JsonValueKind.Object
            || !forkSource.TryGetProperty("repository", out JsonElement repository)
            || repository.ValueKind != JsonValueKind.Object)
        {
            return (repositoryId, repositoryName, projectName);
        }

        string sourceRepositoryId = GetString(repository, "id");
        if (sourceRepositoryId.Length == 0)
        {
            return (repositoryId, repositoryName, projectName);
        }

        string sourceRepositoryName = GetString(repository, "name");
        string sourceProjectName = projectName;
        if (repository.TryGetProperty("project", out JsonElement project)
            && project.ValueKind == JsonValueKind.Object)
        {
            string value = GetString(project, "name");
            if (value.Length != 0)
            {
                sourceProjectName = value;
            }
        }

        return (
            sourceRepositoryId,
            sourceRepositoryName.Length == 0 ? repositoryName : sourceRepositoryName,
            sourceProjectName);
    }

    private static bool GetBoolean(JsonElement value, string propertyName)
    {
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.True;
    }

    private static bool TryGetJsonArray(JsonElement value, out JsonElement array)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            array = value;
            return true;
        }

        if (value.TryGetProperty("value", out array)
            && array.ValueKind == JsonValueKind.Array)
        {
            return true;
        }

        array = default;
        return false;
    }

    private static bool TryGetJsonInt32(JsonElement value, string propertyName, out int propertyValue)
    {
        propertyValue = 0;
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt32(out propertyValue);
    }

    private static bool TryGetReleaseArtifactBuildId(JsonElement artifact, out int buildId)
    {
        buildId = 0;
        if (!artifact.TryGetProperty("definitionReference", out JsonElement definitionReference)
            || definitionReference.ValueKind != JsonValueKind.Object
            || !definitionReference.TryGetProperty("version", out JsonElement version)
            || version.ValueKind != JsonValueKind.Object
            || !TryGetJsonString(version, "id", out string value))
        {
            return false;
        }

        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out buildId)
            && buildId > 0;
    }

    private static string GetReleaseArtifactProjectName(AzureDevOpsSourceOptions options, JsonElement artifact)
    {
        if (artifact.TryGetProperty("definitionReference", out JsonElement definitionReference)
            && definitionReference.ValueKind == JsonValueKind.Object
            && definitionReference.TryGetProperty("project", out JsonElement project)
            && project.ValueKind == JsonValueKind.Object
            && TryGetJsonString(project, "name", out string projectName))
        {
            return projectName;
        }

        return options.Project;
    }

    private static string GetArtifactName(JsonElement artifact)
    {
        string artifactName = GetString(artifact, "name");
        if (artifactName.Length != 0)
        {
            return artifactName;
        }

        return TryGetJsonInt32(artifact, "id", out int artifactId)
            ? artifactId.ToString(CultureInfo.InvariantCulture)
            : "artifact";
    }

    private static string GetFirstWikiVersion(JsonElement wiki)
    {
        if (!wiki.TryGetProperty("versions", out JsonElement versions)
            || versions.ValueKind != JsonValueKind.Array)
        {
            return string.Empty;
        }

        foreach (JsonElement version in versions.EnumerateArray())
        {
            if (TryGetJsonString(version, "version", out string value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string NormalizeWikiMappedPath(string value)
    {
        string normalized = value.Replace('\\', '/').Trim();
        return normalized is "" or "/" ? string.Empty : normalized;
    }

    private static string NormalizeSourceRefName(string value)
    {
        string normalized = value.Trim();
        const string HeadsPrefix = "refs/heads/";
        return normalized.StartsWith(HeadsPrefix, StringComparison.OrdinalIgnoreCase)
            ? normalized[HeadsPrefix.Length..]
            : normalized;
    }

    private static string CreateDisplayPath(string projectName, string repositoryName, string itemPath)
    {
        return string.Concat(
            "azure-devops/",
            EscapeDisplaySegment(projectName),
            "/",
            EscapeDisplaySegment(repositoryName),
            "/",
            NormalizeRemoteItemPath(itemPath));
    }

    private static string CreateWikiDisplayPath(string projectName, string wikiName, string itemPath)
    {
        return string.Concat(
            "azure-devops-wiki/",
            EscapeDisplaySegment(projectName),
            "/",
            EscapeDisplaySegment(wikiName),
            "/",
            NormalizeRemoteItemPath(itemPath));
    }

    private static string CreateBuildArtifactDisplayPath(AzureDevOpsSourceOptions options, string artifactName)
    {
        return string.Concat(
            "azure-devops-build/",
            EscapeDisplaySegment(options.Project),
            "/",
            options.BuildId.ToString(CultureInfo.InvariantCulture),
            "/artifacts/",
            EscapeDisplaySegment(artifactName),
            ".zip");
    }

    private static string CreateReleaseArtifactDisplayPath(
        AzureDevOpsSourceOptions options,
        string releaseArtifactAlias,
        string buildArtifactName)
    {
        return string.Concat(
            "azure-devops-release/",
            EscapeDisplaySegment(options.Project),
            "/",
            options.ReleaseId.ToString(CultureInfo.InvariantCulture),
            "/artifacts/",
            EscapeDisplaySegment(releaseArtifactAlias),
            "/",
            EscapeDisplaySegment(buildArtifactName),
            ".zip");
    }

    private static string CreateBuildLogDisplayPath(AzureDevOpsSourceOptions options, int logId)
    {
        return string.Concat(
            "azure-devops-build/",
            EscapeDisplaySegment(options.Project),
            "/",
            options.BuildId.ToString(CultureInfo.InvariantCulture),
            "/logs/",
            logId.ToString(CultureInfo.InvariantCulture),
            ".log");
    }

    private static bool IsRedirect(HttpResponseMessage response)
    {
        int statusCode = (int)response.StatusCode;
        return statusCode is >= 300 and <= 399;
    }

    private static bool IsAllowedAzureDevOpsUri(Uri endpoint, Uri uri)
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

    private static bool IsAllowedAzureDevOpsRedirectUri(Uri endpoint, Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.Scheme is not "https" and not "http")
        {
            return false;
        }

        if (uri.Scheme.Equals("http", StringComparison.Ordinal)
            && !endpoint.Scheme.Equals("http", StringComparison.Ordinal))
        {
            return false;
        }

        bool sameHost = uri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase);
        bool subdomainOfEndpoint = uri.Host.EndsWith(string.Concat(".", endpoint.Host), StringComparison.OrdinalIgnoreCase);
        bool publicAzureDevOpsArtifactHost = IsPublicAzureDevOpsEndpoint(endpoint)
            && (uri.Host.EndsWith(".blob.core.windows.net", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".vsassets.io", StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase));
        return sameHost || subdomainOfEndpoint || publicAzureDevOpsArtifactHost;
    }

    private static bool IsPublicAzureDevOpsEndpoint(Uri endpoint)
    {
        return endpoint.Host.Equals("dev.azure.com", StringComparison.OrdinalIgnoreCase)
            || endpoint.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase);
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

    private static bool IsCancellationRequested(AzureDevOpsSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
