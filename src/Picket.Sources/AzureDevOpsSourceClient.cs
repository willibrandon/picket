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

            if (options.Branch.Length == 0
                && hasDefaultBranchMetadata
                && defaultBranch.Length == 0)
            {
                options.WarningSink?.Invoke($"skipping Azure DevOps repository {name} because it does not have a default branch");
                continue;
            }

            await AddRepositoryFilesAsync(options, id, name, projectName, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeWikis && !IsCancellationRequested(options))
        {
            await AddWikiFilesAsync(options, sourceFiles, cancellationToken).ConfigureAwait(false);
        }

        return sourceFiles;
    }

    private async Task<List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)>> ListRepositoriesAsync(
        AzureDevOpsSourceOptions options,
        CancellationToken cancellationToken)
    {
        var repositories = new List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)>();
        string continuationToken = string.Empty;
        do
        {
            Uri uri = CreateRepositoryListUri(options, continuationToken);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await AddRepositoriesAsync(response, repositories, cancellationToken).ConfigureAwait(false);
            continuationToken = ReadContinuationToken(response);
        }
        while (continuationToken.Length != 0 && !IsCancellationRequested(options));

        return repositories;
    }

    private async Task AddRepositoryFilesAsync(
        AzureDevOpsSourceOptions options,
        string repositoryId,
        string repositoryName,
        string projectName,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        string continuationToken = string.Empty;
        do
        {
            Uri uri = CreateItemListUri(options, projectName, repositoryId, continuationToken);
            using HttpResponseMessage response = await SendAsync(options, uri, acceptJson: true, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                WarnUnsuccessfulResponse(options, response, $"skipping Azure DevOps repository {repositoryName}");
                return;
            }

            await AddItemFilesAsync(options, response, repositoryId, repositoryName, projectName, sourceFiles, cancellationToken).ConfigureAwait(false);
            continuationToken = ReadContinuationToken(response);
        }
        while (continuationToken.Length != 0 && !IsCancellationRequested(options));
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
        do
        {
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
        while (continuationToken.Length != 0 && !IsCancellationRequested(options));
    }

    private async Task AddItemFilesAsync(
        AzureDevOpsSourceOptions options,
        HttpResponseMessage response,
        string repositoryId,
        string repositoryName,
        string projectName,
        List<SourceFile> sourceFiles,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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

            Uri downloadUri = CreateItemDownloadUri(options, projectName, repositoryId, path);
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
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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

        if (options.MaxFileBytes.HasValue
            && response.Content.Headers.ContentLength.HasValue
            && response.Content.Headers.ContentLength.Value > options.MaxFileBytes.Value)
        {
            options.WarningSink?.Invoke($"Azure DevOps file byte limit skipped {displayPath}");
            return null;
        }

        return await ReadContentWithinLimitAsync(response, options, displayPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(
        AzureDevOpsSourceOptions options,
        Uri uri,
        bool acceptJson,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptJson ? "application/json" : "application/octet-stream"));
        request.Headers.Authorization = CreateAuthorizationHeader(options);
        return await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private static async Task AddRepositoriesAsync(
        HttpResponseMessage response,
        List<(string Id, string Name, string ProjectName, string DefaultBranch, bool HasDefaultBranchMetadata)> repositories,
        CancellationToken cancellationToken)
    {
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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
                        options.WarningSink?.Invoke($"Azure DevOps file byte limit skipped {displayPath}");
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
        string continuationToken)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("recursionLevel", "Full"),
            new("includeContentMetadata", "true")
        };
        AddBranchQuery(options, query);
        AddApiQuery(query, continuationToken);
        return CreateUri(options.Endpoint, [projectName, "_apis", "git", "repositories", repositoryId, "items"], query);
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
        string path)
    {
        var query = new List<KeyValuePair<string, string>>
        {
            new("path", path),
            new("download", "true")
        };
        AddBranchQuery(options, query);
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

    private static void AddBranchQuery(AzureDevOpsSourceOptions options, List<KeyValuePair<string, string>> query)
    {
        AddBranchQuery(options.Branch, query);
    }

    private static void AddBranchQuery(string branch, List<KeyValuePair<string, string>> query)
    {
        if (branch.Length == 0)
        {
            return;
        }

        query.Add(new KeyValuePair<string, string>("versionDescriptor.version", branch));
        query.Add(new KeyValuePair<string, string>("versionDescriptor.versionType", "branch"));
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

    private static bool GetBoolean(JsonElement value, string propertyName)
    {
        return value.TryGetProperty(propertyName, out JsonElement property)
            && property.ValueKind == JsonValueKind.True;
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

    private static string CreateDisplayPath(string projectName, string repositoryName, string itemPath)
    {
        string normalizedItemPath = itemPath.Replace('\\', '/').TrimStart('/');
        return string.Concat(
            "azure-devops/",
            EscapeDisplaySegment(projectName),
            "/",
            EscapeDisplaySegment(repositoryName),
            "/",
            normalizedItemPath);
    }

    private static string CreateWikiDisplayPath(string projectName, string wikiName, string itemPath)
    {
        string normalizedItemPath = itemPath.Replace('\\', '/').TrimStart('/');
        return string.Concat(
            "azure-devops-wiki/",
            EscapeDisplaySegment(projectName),
            "/",
            EscapeDisplaySegment(wikiName),
            "/",
            normalizedItemPath);
    }

    private static string EscapeDisplaySegment(string value)
    {
        return Uri.EscapeDataString(value).Replace("%2F", "_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCancellationRequested(AzureDevOpsSourceOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
