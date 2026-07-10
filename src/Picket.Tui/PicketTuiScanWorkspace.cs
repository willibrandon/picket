using System.ComponentModel;
using System.Globalization;
using System.Text;

namespace Picket.Tui;

/// <summary>
/// Holds mutable state for the interactive scan workspace.
/// </summary>
internal sealed class PicketTuiScanWorkspace
{
    private const string DefaultReportPath = "picket-results/picket-tui.jsonl";
    private const int MaxCapturedOutputLineLength = 180;
    private const int MaxCapturedOutputLines = 500;
    private static readonly char[] s_argumentQuoteCharacters = [' ', '\t', '"'];
    private static readonly string[] s_azureBlobTokenKinds = ["bearer", "sas"];
    private static readonly string[] s_azureDevOpsTokenKinds = ["pat", "bearer"];
    private static readonly string[] s_bitbucketTokenKinds = ["bearer", "app-password"];
    private static readonly string[] s_giteaIssueStates = ["all", "open", "closed"];
    private static readonly string[] s_githubIssueStates = ["all", "open", "closed"];
    private static readonly string[] s_githubRepositoryTypes = ["all", "public", "private", "forks", "sources", "owner", "member"];
    private static readonly string[] s_reportFormats = ["jsonl", "json", "sarif", "html", "csv", "junit", "gitlab", "toon"];
    private static readonly string[] s_resultFilterDisplayLabels = ["all", "unknown", "valid", "test", "invalid", "active", "inactive", "skipped", "error"];
    private static readonly string[] s_resultFilters = ["all", "unknown", "structurally-valid", "test-credential", "invalid", "active", "inactive", "skipped", "error"];
    private static readonly string[] s_scanSettingPages = ["Source", "Output", "Validation", "Limits"];
    private static readonly string[] s_targetModeLabels = ["Local", "GitHub", "Azure DevOps", "GitLab", "Gitea", "Bitbucket", "S3", "GCS", "Azure Blob", "Docker", "OCI"];
    private readonly List<string> _capturedOutputLines = [];
    private readonly IPicketTuiScanExecutor _executor;
    private readonly Lock _outputLock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiScanWorkspace" /> class.
    /// </summary>
    /// <param name="executor">The executor that runs the scanner command.</param>
    internal PicketTuiScanWorkspace(IPicketTuiScanExecutor executor)
    {
        _executor = executor;
    }

    /// <summary>
    /// Gets the selectable Azure Blob token kinds.
    /// </summary>
    internal static IReadOnlyList<string> AzureBlobTokenKinds => s_azureBlobTokenKinds;

    /// <summary>
    /// Gets the selectable Azure DevOps token kinds.
    /// </summary>
    internal static IReadOnlyList<string> AzureDevOpsTokenKinds => s_azureDevOpsTokenKinds;

    /// <summary>
    /// Gets the selectable Bitbucket token kinds.
    /// </summary>
    internal static IReadOnlyList<string> BitbucketTokenKinds => s_bitbucketTokenKinds;

    /// <summary>
    /// Gets the selectable Gitea issue states.
    /// </summary>
    internal static IReadOnlyList<string> GiteaIssueStates => s_giteaIssueStates;

    /// <summary>
    /// Gets the selectable GitHub issue states.
    /// </summary>
    internal static IReadOnlyList<string> GitHubIssueStates => s_githubIssueStates;

    /// <summary>
    /// Gets the selectable GitHub repository type filters.
    /// </summary>
    internal static IReadOnlyList<string> GitHubRepositoryTypes => s_githubRepositoryTypes;

    /// <summary>
    /// Gets the selectable report formats.
    /// </summary>
    internal static IReadOnlyList<string> ReportFormats => s_reportFormats;

    /// <summary>
    /// Gets the selectable result filters.
    /// </summary>
    internal static IReadOnlyList<string> ResultFilters => s_resultFilters;

    /// <summary>
    /// Gets compact result filter labels for terminal display.
    /// </summary>
    internal static IReadOnlyList<string> ResultFilterDisplayLabels => s_resultFilterDisplayLabels;

    /// <summary>
    /// Gets the selectable scan settings pages.
    /// </summary>
    internal static IReadOnlyList<string> ScanSettingPages => s_scanSettingPages;

    /// <summary>
    /// Gets the selectable target mode labels.
    /// </summary>
    internal static IReadOnlyList<string> TargetModeLabels => s_targetModeLabels;

    /// <summary>
    /// Gets the selected scan target mode.
    /// </summary>
    internal PicketTuiScanTargetMode TargetMode { get; private set; }

    /// <summary>
    /// Gets the local filesystem path to scan.
    /// </summary>
    internal string LocalPath { get; private set; } = ".";

    /// <summary>
    /// Gets the local Docker image archive path to scan.
    /// </summary>
    internal string DockerArchivePath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the local OCI image-layout archive path to scan.
    /// </summary>
    internal string OciArchivePath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub repository selector.
    /// </summary>
    internal string GitHubRepository { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub organization selector.
    /// </summary>
    internal string GitHubOrganization { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub user selector.
    /// </summary>
    internal string GitHubUser { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub repository type filter.
    /// </summary>
    internal string GitHubRepositoryType { get; private set; } = "all";

    /// <summary>
    /// Gets the GitHub gist selector.
    /// </summary>
    internal string GitHubGist { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether the authenticated user's GitHub gists are included.
    /// </summary>
    internal bool IncludeGitHubGists { get; private set; }

    /// <summary>
    /// Gets the public GitHub user whose gists should be scanned.
    /// </summary>
    internal string GitHubUserGists { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub ref selector.
    /// </summary>
    internal string GitHubRef { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub pull request selector.
    /// </summary>
    internal string GitHubPullRequest { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitHub token environment variable name.
    /// </summary>
    internal string GitHubTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether GitHub issue bodies and comments are included.
    /// </summary>
    internal bool IncludeGitHubIssues { get; private set; }

    /// <summary>
    /// Gets the GitHub issue state filter.
    /// </summary>
    internal string GitHubIssueState { get; private set; } = "all";

    /// <summary>
    /// Gets a value indicating whether GitHub releases and release assets are included.
    /// </summary>
    internal bool IncludeGitHubReleases { get; private set; }

    /// <summary>
    /// Gets a value indicating whether GitHub Actions artifacts are included.
    /// </summary>
    internal bool IncludeGitHubActionsArtifacts { get; private set; }

    /// <summary>
    /// Gets the GitHub source API endpoint.
    /// </summary>
    internal string GitHubSourceApiEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps Services or Server endpoint.
    /// </summary>
    internal string AzureDevOpsEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps organization selector.
    /// </summary>
    internal string AzureDevOpsOrganization { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps project selector.
    /// </summary>
    internal string AzureDevOpsProject { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps repository selector.
    /// </summary>
    internal string AzureDevOpsRepository { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps branch selector.
    /// </summary>
    internal string AzureDevOpsBranch { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps pull request selector.
    /// </summary>
    internal string AzureDevOpsPullRequest { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps token environment variable name.
    /// </summary>
    internal string AzureDevOpsTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure DevOps token authentication kind.
    /// </summary>
    internal string AzureDevOpsTokenKind { get; private set; } = "pat";

    /// <summary>
    /// Gets a value indicating whether Azure DevOps wikis are included.
    /// </summary>
    internal bool IncludeAzureDevOpsWikis { get; private set; }

    /// <summary>
    /// Gets the Azure Pipelines build ID used for artifact or log scans.
    /// </summary>
    internal string AzureDevOpsBuildId { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the classic Azure DevOps release ID used for release artifact scans.
    /// </summary>
    internal string AzureDevOpsReleaseId { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Pipelines artifact download cap in decimal megabytes.
    /// </summary>
    internal string AzureDevOpsMaxArtifactMegabytes { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Pipelines log download cap in decimal megabytes.
    /// </summary>
    internal string AzureDevOpsMaxLogMegabytes { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether non-public source endpoints are allowed.
    /// </summary>
    internal bool AllowNonPublicSourceEndpoints { get; private set; }

    /// <summary>
    /// Gets a value indicating whether insecure source endpoints are allowed.
    /// </summary>
    internal bool AllowInsecureSourceEndpoints { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Azure Pipelines build artifacts are included.
    /// </summary>
    internal bool IncludeAzureDevOpsArtifacts { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Azure Pipelines build logs are included.
    /// </summary>
    internal bool IncludeAzureDevOpsLogs { get; private set; }

    /// <summary>
    /// Gets a value indicating whether classic Azure DevOps release artifacts are included.
    /// </summary>
    internal bool IncludeAzureDevOpsReleaseArtifacts { get; private set; }

    /// <summary>
    /// Gets the GitLab project selector.
    /// </summary>
    internal string GitLabProject { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab group selector.
    /// </summary>
    internal string GitLabGroup { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab ref selector.
    /// </summary>
    internal string GitLabRef { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab merge request selector.
    /// </summary>
    internal string GitLabMergeRequest { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab pipeline selector.
    /// </summary>
    internal string GitLabPipelineId { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab token environment variable name.
    /// </summary>
    internal string GitLabTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the GitLab API endpoint.
    /// </summary>
    internal string GitLabApiEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether GitLab subgroup projects are included.
    /// </summary>
    internal bool IncludeGitLabSubgroups { get; private set; }

    /// <summary>
    /// Gets a value indicating whether GitLab snippets are included.
    /// </summary>
    internal bool IncludeGitLabSnippets { get; private set; }

    /// <summary>
    /// Gets a value indicating whether GitLab job artifact archives are included.
    /// </summary>
    internal bool IncludeGitLabJobArtifacts { get; private set; }

    /// <summary>
    /// Gets a value indicating whether GitLab job logs are included.
    /// </summary>
    internal bool IncludeGitLabJobLogs { get; private set; }

    /// <summary>
    /// Gets a value indicating whether GitLab generic package files are included.
    /// </summary>
    internal bool IncludeGitLabPackages { get; private set; }

    /// <summary>
    /// Gets the Gitea repository selector.
    /// </summary>
    internal string GiteaRepository { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea organization selector.
    /// </summary>
    internal string GiteaOrganization { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea user selector.
    /// </summary>
    internal string GiteaUser { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea ref selector.
    /// </summary>
    internal string GiteaRef { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea pull request selector.
    /// </summary>
    internal string GiteaPullRequest { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea issue state filter.
    /// </summary>
    internal string GiteaIssueState { get; private set; } = "all";

    /// <summary>
    /// Gets the Gitea Actions run selector.
    /// </summary>
    internal string GiteaActionsRunId { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea generic package owner selector.
    /// </summary>
    internal string GiteaGenericPackageOwner { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea generic package name selector.
    /// </summary>
    internal string GiteaGenericPackageName { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea generic package version selector.
    /// </summary>
    internal string GiteaGenericPackageVersion { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea generic package file selector.
    /// </summary>
    internal string GiteaGenericPackageFile { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea token environment variable name.
    /// </summary>
    internal string GiteaTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Gitea API endpoint.
    /// </summary>
    internal string GiteaApiEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether Gitea issues are included.
    /// </summary>
    internal bool IncludeGiteaIssues { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Gitea releases are included.
    /// </summary>
    internal bool IncludeGiteaReleases { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Gitea Actions artifacts are included.
    /// </summary>
    internal bool IncludeGiteaActionsArtifacts { get; private set; }

    /// <summary>
    /// Gets the Bitbucket repository selector.
    /// </summary>
    internal string BitbucketRepository { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket workspace selector.
    /// </summary>
    internal string BitbucketWorkspace { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket project selector.
    /// </summary>
    internal string BitbucketProject { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket ref selector.
    /// </summary>
    internal string BitbucketRef { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket pull request selector.
    /// </summary>
    internal string BitbucketPullRequest { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket pipeline selector.
    /// </summary>
    internal string BitbucketPipelineId { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket token environment variable name.
    /// </summary>
    internal string BitbucketTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket username environment variable name used for app-password authentication.
    /// </summary>
    internal string BitbucketUsernameEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Bitbucket token authentication kind.
    /// </summary>
    internal string BitbucketTokenKind { get; private set; } = "bearer";

    /// <summary>
    /// Gets the Bitbucket API endpoint.
    /// </summary>
    internal string BitbucketApiEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether Bitbucket download artifacts are included.
    /// </summary>
    internal bool IncludeBitbucketDownloads { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Bitbucket pipeline logs are included.
    /// </summary>
    internal bool IncludeBitbucketPipelineLogs { get; private set; }

    /// <summary>
    /// Gets a value indicating whether Bitbucket workspace snippets are included.
    /// </summary>
    internal bool IncludeBitbucketSnippets { get; private set; }

    /// <summary>
    /// Gets the S3 bucket selector.
    /// </summary>
    internal string S3Bucket { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the S3 region used for request signing.
    /// </summary>
    internal string S3Region { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the S3-compatible endpoint URI.
    /// </summary>
    internal string S3Endpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the S3 object key prefix.
    /// </summary>
    internal string S3Prefix { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the S3 access key ID environment variable name.
    /// </summary>
    internal string S3AccessKeyIdEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the S3 secret access key environment variable name.
    /// </summary>
    internal string S3SecretAccessKeyEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the optional S3 session token environment variable name.
    /// </summary>
    internal string S3SessionTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Google Cloud Storage bucket selector.
    /// </summary>
    internal string GcsBucket { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Google Cloud Storage JSON API endpoint URI.
    /// </summary>
    internal string GcsEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Google Cloud Storage object prefix.
    /// </summary>
    internal string GcsPrefix { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Google Cloud Storage bearer token environment variable name.
    /// </summary>
    internal string GcsTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the optional Google Cloud Storage requester-pays billing project.
    /// </summary>
    internal string GcsUserProject { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Blob Storage endpoint URI.
    /// </summary>
    internal string AzureBlobEndpoint { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Blob Storage container selector.
    /// </summary>
    internal string AzureBlobContainer { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Blob Storage blob prefix.
    /// </summary>
    internal string AzureBlobPrefix { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Blob Storage credential environment variable name.
    /// </summary>
    internal string AzureBlobTokenEnvironmentVariable { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the Azure Blob Storage credential kind.
    /// </summary>
    internal string AzureBlobTokenKind { get; private set; } = "bearer";

    /// <summary>
    /// Gets the native profile name.
    /// </summary>
    internal string Profile { get; private set; } = "picket";

    /// <summary>
    /// Gets the optional config path.
    /// </summary>
    internal string ConfigPath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the optional ignore path.
    /// </summary>
    internal string IgnorePath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether native ignore files are disabled.
    /// </summary>
    internal bool NoIgnore { get; private set; }

    /// <summary>
    /// Gets a value indicating whether live verification is enabled.
    /// </summary>
    internal bool Verify { get; private set; }

    /// <summary>
    /// Gets a value indicating whether only verified findings are emitted.
    /// </summary>
    internal bool OnlyVerified { get; private set; }

    /// <summary>
    /// Gets the validation result filter.
    /// </summary>
    internal string ResultFilter { get; private set; } = "all";

    /// <summary>
    /// Gets the report format.
    /// </summary>
    internal string ReportFormat { get; private set; } = "jsonl";

    /// <summary>
    /// Gets the report path.
    /// </summary>
    internal string ReportPath { get; private set; } = DefaultReportPath;

    /// <summary>
    /// Gets the redaction percentage.
    /// </summary>
    internal string RedactionPercent { get; private set; } = "100";

    /// <summary>
    /// Gets the maximum target file size in decimal megabytes.
    /// </summary>
    internal string MaxTargetMegabytes { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the maximum archive nesting depth.
    /// </summary>
    internal string MaxArchiveDepth { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the maximum archive entries.
    /// </summary>
    internal string MaxArchiveEntries { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the maximum decompressed archive bytes in decimal megabytes.
    /// </summary>
    internal string MaxArchiveMegabytes { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the maximum archive compression ratio.
    /// </summary>
    internal string MaxArchiveRatio { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the scan timeout in seconds.
    /// </summary>
    internal string TimeoutSeconds { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the selected scan settings page index.
    /// </summary>
    internal int ScanSettingPageIndex { get; private set; }

    /// <summary>
    /// Gets a value indicating whether a scan is currently running.
    /// </summary>
    internal bool IsRunning { get; private set; }

    /// <summary>
    /// Gets the last scan exit code.
    /// </summary>
    internal int? LastExitCode { get; private set; }

    /// <summary>
    /// Gets the time the last scan started.
    /// </summary>
    internal DateTimeOffset? LastStartedAt { get; private set; }

    /// <summary>
    /// Gets the time the last scan completed.
    /// </summary>
    internal DateTimeOffset? LastCompletedAt { get; private set; }

    /// <summary>
    /// Gets the elapsed time for the last completed scan.
    /// </summary>
    internal TimeSpan? LastElapsed => LastStartedAt.HasValue && LastCompletedAt.HasValue
        ? LastCompletedAt.GetValueOrDefault() - LastStartedAt.GetValueOrDefault()
        : null;

    /// <summary>
    /// Gets the last scan status text.
    /// </summary>
    internal string Status { get; private set; } = "Ready to scan";

    /// <summary>
    /// Gets the last scan diagnostic text.
    /// </summary>
    internal string LastMessage { get; private set; } = "No scan has run in this session.";

    /// <summary>
    /// Gets the captured scanner output lines from the last scan.
    /// </summary>
    internal IReadOnlyList<string> CapturedOutputLines
    {
        get
        {
            lock (_outputLock)
            {
                return [.. _capturedOutputLines];
            }
        }
    }

    /// <summary>
    /// Gets display-ready captured scanner output from the last scan.
    /// </summary>
    internal string CapturedOutputText
    {
        get
        {
            IReadOnlyList<string> lines = CapturedOutputLines;
            return lines.Count == 0
                ? "No scanner output captured."
                : string.Join(Environment.NewLine, lines);
        }
    }

    /// <summary>
    /// Marks an existing report as loaded by the scan workspace.
    /// </summary>
    /// <param name="reportPath">The loaded report path.</param>
    /// <param name="findingCount">The number of findings loaded from the report.</param>
    internal void MarkReportLoaded(string reportPath, int findingCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ClearCapturedOutput();
        LastExitCode = null;
        LastStartedAt = null;
        LastCompletedAt = null;
        Status = findingCount == 0
            ? "Loaded previous scan: no findings"
            : "Loaded previous scan: findings loaded";
        LastMessage = string.Concat(
            "Loaded ",
            findingCount.ToString(CultureInfo.InvariantCulture),
            " findings from ",
            reportPath);
    }

    /// <summary>
    /// Marks the running scan as cancellation-requested before the scanner process exits.
    /// </summary>
    internal void MarkCancellationRequested()
    {
        if (!IsRunning)
        {
            return;
        }

        Status = "Cancelling scan";
        LastMessage = "Cancellation requested; waiting for the scanner process to stop.";
        CaptureMessageOutput("status", LastMessage);
    }

    /// <summary>
    /// Gets the selected target mode index.
    /// </summary>
    internal int TargetModeIndex => TargetMode switch
    {
        PicketTuiScanTargetMode.Local => 0,
        PicketTuiScanTargetMode.GitHub => 1,
        PicketTuiScanTargetMode.AzureDevOps => 2,
        PicketTuiScanTargetMode.GitLab => 3,
        PicketTuiScanTargetMode.Gitea => 4,
        PicketTuiScanTargetMode.Bitbucket => 5,
        PicketTuiScanTargetMode.S3 => 6,
        PicketTuiScanTargetMode.Gcs => 7,
        PicketTuiScanTargetMode.AzureBlob => 8,
        PicketTuiScanTargetMode.DockerArchive => 9,
        PicketTuiScanTargetMode.OciArchive => 10,
        _ => 0,
    };

    /// <summary>
    /// Gets the selected Azure Blob token kind index.
    /// </summary>
    internal int AzureBlobTokenKindIndex => IndexOf(s_azureBlobTokenKinds, AzureBlobTokenKind);

    /// <summary>
    /// Gets the selected GitHub issue state index.
    /// </summary>
    internal int GitHubIssueStateIndex => IndexOf(s_githubIssueStates, GitHubIssueState);

    /// <summary>
    /// Gets the selected GitHub repository type index.
    /// </summary>
    internal int GitHubRepositoryTypeIndex => IndexOf(s_githubRepositoryTypes, GitHubRepositoryType);

    /// <summary>
    /// Gets the selected Azure DevOps token kind index.
    /// </summary>
    internal int AzureDevOpsTokenKindIndex => IndexOf(s_azureDevOpsTokenKinds, AzureDevOpsTokenKind);

    /// <summary>
    /// Gets the selected Gitea issue state index.
    /// </summary>
    internal int GiteaIssueStateIndex => IndexOf(s_giteaIssueStates, GiteaIssueState);

    /// <summary>
    /// Gets the selected Bitbucket token kind index.
    /// </summary>
    internal int BitbucketTokenKindIndex => IndexOf(s_bitbucketTokenKinds, BitbucketTokenKind);

    /// <summary>
    /// Gets the selected report format index.
    /// </summary>
    internal int ReportFormatIndex => IndexOf(s_reportFormats, ReportFormat);

    /// <summary>
    /// Gets the selected result filter index.
    /// </summary>
    internal int ResultFilterIndex => IndexOf(s_resultFilters, ResultFilter);

    /// <summary>
    /// Sets the selected scan settings page by index.
    /// </summary>
    /// <param name="index">The selected scan settings page index.</param>
    internal void SetScanSettingPageByIndex(int index)
    {
        ScanSettingPageIndex = Math.Clamp(index, 0, s_scanSettingPages.Length - 1);
    }

    /// <summary>
    /// Sets the selected target mode by index.
    /// </summary>
    /// <param name="index">The target mode index.</param>
    internal void SetTargetMode(int index)
    {
        TargetMode = index switch
        {
            1 => PicketTuiScanTargetMode.GitHub,
            2 => PicketTuiScanTargetMode.AzureDevOps,
            3 => PicketTuiScanTargetMode.GitLab,
            4 => PicketTuiScanTargetMode.Gitea,
            5 => PicketTuiScanTargetMode.Bitbucket,
            6 => PicketTuiScanTargetMode.S3,
            7 => PicketTuiScanTargetMode.Gcs,
            8 => PicketTuiScanTargetMode.AzureBlob,
            9 => PicketTuiScanTargetMode.DockerArchive,
            10 => PicketTuiScanTargetMode.OciArchive,
            _ => PicketTuiScanTargetMode.Local,
        };
    }

    /// <summary>
    /// Sets the local filesystem path.
    /// </summary>
    /// <param name="value">The local path.</param>
    internal void SetLocalPath(string value) => LocalPath = value;

    /// <summary>
    /// Sets the local Docker image archive path.
    /// </summary>
    /// <param name="value">The archive path.</param>
    internal void SetDockerArchivePath(string value) => DockerArchivePath = value;

    /// <summary>
    /// Sets the local OCI image-layout archive path.
    /// </summary>
    /// <param name="value">The archive path.</param>
    internal void SetOciArchivePath(string value) => OciArchivePath = value;

    /// <summary>
    /// Sets the GitHub repository selector.
    /// </summary>
    /// <param name="value">The repository selector.</param>
    internal void SetGitHubRepository(string value) => GitHubRepository = value;

    /// <summary>
    /// Sets the GitHub organization selector.
    /// </summary>
    /// <param name="value">The organization selector.</param>
    internal void SetGitHubOrganization(string value) => GitHubOrganization = value;

    /// <summary>
    /// Sets the GitHub user selector.
    /// </summary>
    /// <param name="value">The user selector.</param>
    internal void SetGitHubUser(string value) => GitHubUser = value;

    /// <summary>
    /// Sets the GitHub repository type filter by index.
    /// </summary>
    /// <param name="index">The selected repository type index.</param>
    internal void SetGitHubRepositoryTypeByIndex(int index) => GitHubRepositoryType = s_githubRepositoryTypes[Math.Clamp(index, 0, s_githubRepositoryTypes.Length - 1)];

    /// <summary>
    /// Sets the GitHub gist selector.
    /// </summary>
    /// <param name="value">The gist selector.</param>
    internal void SetGitHubGist(string value) => GitHubGist = value;

    /// <summary>
    /// Sets whether the authenticated user's GitHub gists are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitHubGists(bool value) => IncludeGitHubGists = value;

    /// <summary>
    /// Sets the public GitHub user whose gists should be scanned.
    /// </summary>
    /// <param name="value">The GitHub user login.</param>
    internal void SetGitHubUserGists(string value) => GitHubUserGists = value;

    /// <summary>
    /// Sets the GitHub ref selector.
    /// </summary>
    /// <param name="value">The ref selector.</param>
    internal void SetGitHubRef(string value) => GitHubRef = value;

    /// <summary>
    /// Sets the GitHub pull request selector.
    /// </summary>
    /// <param name="value">The pull request selector.</param>
    internal void SetGitHubPullRequest(string value) => GitHubPullRequest = value;

    /// <summary>
    /// Sets the GitHub token environment variable name.
    /// </summary>
    /// <param name="value">The token environment variable name.</param>
    internal void SetGitHubTokenEnvironmentVariable(string value) => GitHubTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets whether GitHub issue bodies and comments are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitHubIssues(bool value) => IncludeGitHubIssues = value;

    /// <summary>
    /// Sets the GitHub issue state filter by index.
    /// </summary>
    /// <param name="index">The selected issue state index.</param>
    internal void SetGitHubIssueStateByIndex(int index) => GitHubIssueState = s_githubIssueStates[Math.Clamp(index, 0, s_githubIssueStates.Length - 1)];

    /// <summary>
    /// Sets whether GitHub releases and release assets are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitHubReleases(bool value) => IncludeGitHubReleases = value;

    /// <summary>
    /// Sets whether GitHub Actions artifacts are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitHubActionsArtifacts(bool value) => IncludeGitHubActionsArtifacts = value;

    /// <summary>
    /// Sets the GitHub source API endpoint.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetGitHubSourceApiEndpoint(string value) => GitHubSourceApiEndpoint = value;

    /// <summary>
    /// Sets the Azure DevOps Services or Server endpoint.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetAzureDevOpsEndpoint(string value) => AzureDevOpsEndpoint = value;

    /// <summary>
    /// Sets the Azure DevOps organization selector.
    /// </summary>
    /// <param name="value">The organization selector.</param>
    internal void SetAzureDevOpsOrganization(string value) => AzureDevOpsOrganization = value;

    /// <summary>
    /// Sets the Azure DevOps project selector.
    /// </summary>
    /// <param name="value">The project selector.</param>
    internal void SetAzureDevOpsProject(string value) => AzureDevOpsProject = value;

    /// <summary>
    /// Sets the Azure DevOps repository selector.
    /// </summary>
    /// <param name="value">The repository selector.</param>
    internal void SetAzureDevOpsRepository(string value) => AzureDevOpsRepository = value;

    /// <summary>
    /// Sets the Azure DevOps branch selector.
    /// </summary>
    /// <param name="value">The branch selector.</param>
    internal void SetAzureDevOpsBranch(string value) => AzureDevOpsBranch = value;

    /// <summary>
    /// Sets the Azure DevOps pull request selector.
    /// </summary>
    /// <param name="value">The pull request selector.</param>
    internal void SetAzureDevOpsPullRequest(string value) => AzureDevOpsPullRequest = value;

    /// <summary>
    /// Sets the Azure DevOps token environment variable name.
    /// </summary>
    /// <param name="value">The token environment variable name.</param>
    internal void SetAzureDevOpsTokenEnvironmentVariable(string value) => AzureDevOpsTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the Azure DevOps token kind by index.
    /// </summary>
    /// <param name="index">The selected token kind index.</param>
    internal void SetAzureDevOpsTokenKindByIndex(int index) => AzureDevOpsTokenKind = s_azureDevOpsTokenKinds[Math.Clamp(index, 0, s_azureDevOpsTokenKinds.Length - 1)];

    /// <summary>
    /// Sets whether Azure DevOps wikis are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeAzureDevOpsWikis(bool value) => IncludeAzureDevOpsWikis = value;

    /// <summary>
    /// Sets the Azure Pipelines build ID.
    /// </summary>
    /// <param name="value">The build ID.</param>
    internal void SetAzureDevOpsBuildId(string value) => AzureDevOpsBuildId = value;

    /// <summary>
    /// Sets the classic Azure DevOps release ID.
    /// </summary>
    /// <param name="value">The release ID.</param>
    internal void SetAzureDevOpsReleaseId(string value) => AzureDevOpsReleaseId = value;

    /// <summary>
    /// Sets the Azure Pipelines artifact cap in decimal megabytes.
    /// </summary>
    /// <param name="value">The artifact cap.</param>
    internal void SetAzureDevOpsMaxArtifactMegabytes(string value) => AzureDevOpsMaxArtifactMegabytes = value;

    /// <summary>
    /// Sets the Azure Pipelines log cap in decimal megabytes.
    /// </summary>
    /// <param name="value">The log cap.</param>
    internal void SetAzureDevOpsMaxLogMegabytes(string value) => AzureDevOpsMaxLogMegabytes = value;

    /// <summary>
    /// Sets whether non-public source endpoints are allowed.
    /// </summary>
    /// <param name="value">The endpoint policy state.</param>
    internal void SetAllowNonPublicSourceEndpoints(bool value) => AllowNonPublicSourceEndpoints = value;

    /// <summary>
    /// Sets whether insecure source endpoints are allowed.
    /// </summary>
    /// <param name="value">The endpoint policy state.</param>
    internal void SetAllowInsecureSourceEndpoints(bool value) => AllowInsecureSourceEndpoints = value;

    /// <summary>
    /// Sets whether Azure Pipelines build artifacts are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeAzureDevOpsArtifacts(bool value) => IncludeAzureDevOpsArtifacts = value;

    /// <summary>
    /// Sets whether Azure Pipelines build logs are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeAzureDevOpsLogs(bool value) => IncludeAzureDevOpsLogs = value;

    /// <summary>
    /// Sets whether classic Azure DevOps release artifacts are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeAzureDevOpsReleaseArtifacts(bool value) => IncludeAzureDevOpsReleaseArtifacts = value;

    /// <summary>
    /// Sets the GitLab project selector.
    /// </summary>
    /// <param name="value">The project selector.</param>
    internal void SetGitLabProject(string value) => GitLabProject = value;

    /// <summary>
    /// Sets the GitLab group selector.
    /// </summary>
    /// <param name="value">The group selector.</param>
    internal void SetGitLabGroup(string value) => GitLabGroup = value;

    /// <summary>
    /// Sets the GitLab ref selector.
    /// </summary>
    /// <param name="value">The ref selector.</param>
    internal void SetGitLabRef(string value) => GitLabRef = value;

    /// <summary>
    /// Sets the GitLab merge request selector.
    /// </summary>
    /// <param name="value">The merge request internal ID.</param>
    internal void SetGitLabMergeRequest(string value) => GitLabMergeRequest = value;

    /// <summary>
    /// Sets the GitLab pipeline selector.
    /// </summary>
    /// <param name="value">The pipeline ID.</param>
    internal void SetGitLabPipelineId(string value) => GitLabPipelineId = value;

    /// <summary>
    /// Sets the GitLab token environment variable name.
    /// </summary>
    /// <param name="value">The token environment variable name.</param>
    internal void SetGitLabTokenEnvironmentVariable(string value) => GitLabTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the GitLab API endpoint.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetGitLabApiEndpoint(string value) => GitLabApiEndpoint = value;

    /// <summary>
    /// Sets whether GitLab subgroup projects are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitLabSubgroups(bool value) => IncludeGitLabSubgroups = value;

    /// <summary>
    /// Sets whether GitLab snippets are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitLabSnippets(bool value) => IncludeGitLabSnippets = value;

    /// <summary>
    /// Sets whether GitLab job artifact archives are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitLabJobArtifacts(bool value) => IncludeGitLabJobArtifacts = value;

    /// <summary>
    /// Sets whether GitLab job logs are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitLabJobLogs(bool value) => IncludeGitLabJobLogs = value;

    /// <summary>
    /// Sets whether GitLab generic package files are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGitLabPackages(bool value) => IncludeGitLabPackages = value;

    /// <summary>
    /// Sets the Gitea repository selector.
    /// </summary>
    /// <param name="value">The repository selector.</param>
    internal void SetGiteaRepository(string value) => GiteaRepository = value;

    /// <summary>
    /// Sets the Gitea organization selector.
    /// </summary>
    /// <param name="value">The organization selector.</param>
    internal void SetGiteaOrganization(string value) => GiteaOrganization = value;

    /// <summary>
    /// Sets the Gitea user selector.
    /// </summary>
    /// <param name="value">The user selector.</param>
    internal void SetGiteaUser(string value) => GiteaUser = value;

    /// <summary>
    /// Sets the Gitea ref selector.
    /// </summary>
    /// <param name="value">The ref selector.</param>
    internal void SetGiteaRef(string value) => GiteaRef = value;

    /// <summary>
    /// Sets the Gitea pull request selector.
    /// </summary>
    /// <param name="value">The pull request ID.</param>
    internal void SetGiteaPullRequest(string value) => GiteaPullRequest = value;

    /// <summary>
    /// Sets the Gitea issue state filter by index.
    /// </summary>
    /// <param name="index">The selected issue state index.</param>
    internal void SetGiteaIssueStateByIndex(int index) => GiteaIssueState = s_giteaIssueStates[Math.Clamp(index, 0, s_giteaIssueStates.Length - 1)];

    /// <summary>
    /// Sets the Gitea Actions run selector.
    /// </summary>
    /// <param name="value">The Actions run ID.</param>
    internal void SetGiteaActionsRunId(string value) => GiteaActionsRunId = value;

    /// <summary>
    /// Sets the Gitea generic package owner selector.
    /// </summary>
    /// <param name="value">The package owner.</param>
    internal void SetGiteaGenericPackageOwner(string value) => GiteaGenericPackageOwner = value;

    /// <summary>
    /// Sets the Gitea generic package name selector.
    /// </summary>
    /// <param name="value">The package name.</param>
    internal void SetGiteaGenericPackageName(string value) => GiteaGenericPackageName = value;

    /// <summary>
    /// Sets the Gitea generic package version selector.
    /// </summary>
    /// <param name="value">The package version.</param>
    internal void SetGiteaGenericPackageVersion(string value) => GiteaGenericPackageVersion = value;

    /// <summary>
    /// Sets the Gitea generic package file selector.
    /// </summary>
    /// <param name="value">The package file name.</param>
    internal void SetGiteaGenericPackageFile(string value) => GiteaGenericPackageFile = value;

    /// <summary>
    /// Sets the Gitea token environment variable name.
    /// </summary>
    /// <param name="value">The token environment variable name.</param>
    internal void SetGiteaTokenEnvironmentVariable(string value) => GiteaTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the Gitea API endpoint.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetGiteaApiEndpoint(string value) => GiteaApiEndpoint = value;

    /// <summary>
    /// Sets whether Gitea issues are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGiteaIssues(bool value) => IncludeGiteaIssues = value;

    /// <summary>
    /// Sets whether Gitea releases are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGiteaReleases(bool value) => IncludeGiteaReleases = value;

    /// <summary>
    /// Sets whether Gitea Actions artifacts are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeGiteaActionsArtifacts(bool value) => IncludeGiteaActionsArtifacts = value;

    /// <summary>
    /// Sets the Bitbucket repository selector.
    /// </summary>
    /// <param name="value">The repository selector.</param>
    internal void SetBitbucketRepository(string value) => BitbucketRepository = value;

    /// <summary>
    /// Sets the Bitbucket workspace selector.
    /// </summary>
    /// <param name="value">The workspace selector.</param>
    internal void SetBitbucketWorkspace(string value) => BitbucketWorkspace = value;

    /// <summary>
    /// Sets the Bitbucket project selector.
    /// </summary>
    /// <param name="value">The project key.</param>
    internal void SetBitbucketProject(string value) => BitbucketProject = value;

    /// <summary>
    /// Sets the Bitbucket ref selector.
    /// </summary>
    /// <param name="value">The ref selector.</param>
    internal void SetBitbucketRef(string value) => BitbucketRef = value;

    /// <summary>
    /// Sets the Bitbucket pull request selector.
    /// </summary>
    /// <param name="value">The pull request ID.</param>
    internal void SetBitbucketPullRequest(string value) => BitbucketPullRequest = value;

    /// <summary>
    /// Sets the Bitbucket pipeline selector.
    /// </summary>
    /// <param name="value">The pipeline ID or UUID.</param>
    internal void SetBitbucketPipelineId(string value) => BitbucketPipelineId = value;

    /// <summary>
    /// Sets the Bitbucket token environment variable name.
    /// </summary>
    /// <param name="value">The token environment variable name.</param>
    internal void SetBitbucketTokenEnvironmentVariable(string value) => BitbucketTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the Bitbucket username environment variable name used for app-password authentication.
    /// </summary>
    /// <param name="value">The username environment variable name.</param>
    internal void SetBitbucketUsernameEnvironmentVariable(string value) => BitbucketUsernameEnvironmentVariable = value;

    /// <summary>
    /// Sets the Bitbucket token kind by index.
    /// </summary>
    /// <param name="index">The selected token kind index.</param>
    internal void SetBitbucketTokenKindByIndex(int index) => BitbucketTokenKind = s_bitbucketTokenKinds[Math.Clamp(index, 0, s_bitbucketTokenKinds.Length - 1)];

    /// <summary>
    /// Sets the Bitbucket API endpoint.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetBitbucketApiEndpoint(string value) => BitbucketApiEndpoint = value;

    /// <summary>
    /// Sets whether Bitbucket download artifacts are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeBitbucketDownloads(bool value) => IncludeBitbucketDownloads = value;

    /// <summary>
    /// Sets whether Bitbucket pipeline logs are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeBitbucketPipelineLogs(bool value) => IncludeBitbucketPipelineLogs = value;

    /// <summary>
    /// Sets whether Bitbucket workspace snippets are included.
    /// </summary>
    /// <param name="value">The include state.</param>
    internal void SetIncludeBitbucketSnippets(bool value) => IncludeBitbucketSnippets = value;

    /// <summary>
    /// Sets the S3 bucket selector.
    /// </summary>
    /// <param name="value">The bucket name.</param>
    internal void SetS3Bucket(string value) => S3Bucket = value;

    /// <summary>
    /// Sets the S3 region used for request signing.
    /// </summary>
    /// <param name="value">The AWS region.</param>
    internal void SetS3Region(string value) => S3Region = value;

    /// <summary>
    /// Sets the S3-compatible endpoint URI.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetS3Endpoint(string value) => S3Endpoint = value;

    /// <summary>
    /// Sets the S3 object key prefix.
    /// </summary>
    /// <param name="value">The object key prefix.</param>
    internal void SetS3Prefix(string value) => S3Prefix = value;

    /// <summary>
    /// Sets the S3 access key ID environment variable name.
    /// </summary>
    /// <param name="value">The environment variable name.</param>
    internal void SetS3AccessKeyIdEnvironmentVariable(string value) => S3AccessKeyIdEnvironmentVariable = value;

    /// <summary>
    /// Sets the S3 secret access key environment variable name.
    /// </summary>
    /// <param name="value">The environment variable name.</param>
    internal void SetS3SecretAccessKeyEnvironmentVariable(string value) => S3SecretAccessKeyEnvironmentVariable = value;

    /// <summary>
    /// Sets the optional S3 session token environment variable name.
    /// </summary>
    /// <param name="value">The environment variable name.</param>
    internal void SetS3SessionTokenEnvironmentVariable(string value) => S3SessionTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the Google Cloud Storage bucket selector.
    /// </summary>
    /// <param name="value">The bucket name.</param>
    internal void SetGcsBucket(string value) => GcsBucket = value;

    /// <summary>
    /// Sets the Google Cloud Storage JSON API endpoint URI.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetGcsEndpoint(string value) => GcsEndpoint = value;

    /// <summary>
    /// Sets the Google Cloud Storage object prefix.
    /// </summary>
    /// <param name="value">The object prefix.</param>
    internal void SetGcsPrefix(string value) => GcsPrefix = value;

    /// <summary>
    /// Sets the Google Cloud Storage bearer token environment variable name.
    /// </summary>
    /// <param name="value">The environment variable name.</param>
    internal void SetGcsTokenEnvironmentVariable(string value) => GcsTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the optional Google Cloud Storage requester-pays billing project.
    /// </summary>
    /// <param name="value">The billing project.</param>
    internal void SetGcsUserProject(string value) => GcsUserProject = value;

    /// <summary>
    /// Sets the Azure Blob Storage endpoint URI.
    /// </summary>
    /// <param name="value">The endpoint URI.</param>
    internal void SetAzureBlobEndpoint(string value) => AzureBlobEndpoint = value;

    /// <summary>
    /// Sets the Azure Blob Storage container selector.
    /// </summary>
    /// <param name="value">The container name.</param>
    internal void SetAzureBlobContainer(string value) => AzureBlobContainer = value;

    /// <summary>
    /// Sets the Azure Blob Storage blob prefix.
    /// </summary>
    /// <param name="value">The blob prefix.</param>
    internal void SetAzureBlobPrefix(string value) => AzureBlobPrefix = value;

    /// <summary>
    /// Sets the Azure Blob Storage credential environment variable name.
    /// </summary>
    /// <param name="value">The environment variable name.</param>
    internal void SetAzureBlobTokenEnvironmentVariable(string value) => AzureBlobTokenEnvironmentVariable = value;

    /// <summary>
    /// Sets the Azure Blob Storage token kind by index.
    /// </summary>
    /// <param name="index">The selected token kind index.</param>
    internal void SetAzureBlobTokenKindByIndex(int index) => AzureBlobTokenKind = s_azureBlobTokenKinds[Math.Clamp(index, 0, s_azureBlobTokenKinds.Length - 1)];

    /// <summary>
    /// Sets the native profile.
    /// </summary>
    /// <param name="value">The profile name.</param>
    internal void SetProfile(string value) => Profile = value;

    /// <summary>
    /// Sets the config path.
    /// </summary>
    /// <param name="value">The config path.</param>
    internal void SetConfigPath(string value) => ConfigPath = value;

    /// <summary>
    /// Sets the ignore path.
    /// </summary>
    /// <param name="value">The ignore path.</param>
    internal void SetIgnorePath(string value) => IgnorePath = value;

    /// <summary>
    /// Sets whether native ignore files are disabled.
    /// </summary>
    /// <param name="value">The no-ignore state.</param>
    internal void SetNoIgnore(bool value) => NoIgnore = value;

    /// <summary>
    /// Sets whether live verification is enabled.
    /// </summary>
    /// <param name="value">The verification state.</param>
    internal void SetVerify(bool value) => Verify = value;

    /// <summary>
    /// Sets whether only verified findings are emitted.
    /// </summary>
    /// <param name="value">The only-verified state.</param>
    internal void SetOnlyVerified(bool value) => OnlyVerified = value;

    /// <summary>
    /// Sets the result filter by index.
    /// </summary>
    /// <param name="index">The filter index.</param>
    internal void SetResultFilterByIndex(int index) => ResultFilter = s_resultFilters[Math.Clamp(index, 0, s_resultFilters.Length - 1)];

    /// <summary>
    /// Sets the report format by index.
    /// </summary>
    /// <param name="index">The report format index.</param>
    internal void SetReportFormatByIndex(int index)
    {
        string oldFormat = ReportFormat;
        ReportFormat = s_reportFormats[Math.Clamp(index, 0, s_reportFormats.Length - 1)];
        if (ReportPath.Equals(GetDefaultReportPath(oldFormat), StringComparison.Ordinal))
        {
            ReportPath = GetDefaultReportPath(ReportFormat);
        }
    }

    /// <summary>
    /// Sets the report path.
    /// </summary>
    /// <param name="value">The report path.</param>
    internal void SetReportPath(string value) => ReportPath = value;

    /// <summary>
    /// Sets the redaction percentage.
    /// </summary>
    /// <param name="value">The redaction percentage.</param>
    internal void SetRedactionPercent(string value) => RedactionPercent = value;

    /// <summary>
    /// Sets the maximum target size in decimal megabytes.
    /// </summary>
    /// <param name="value">The maximum target size.</param>
    internal void SetMaxTargetMegabytes(string value) => MaxTargetMegabytes = value;

    /// <summary>
    /// Sets the maximum archive depth.
    /// </summary>
    /// <param name="value">The maximum archive depth.</param>
    internal void SetMaxArchiveDepth(string value) => MaxArchiveDepth = value;

    /// <summary>
    /// Sets the maximum archive entries.
    /// </summary>
    /// <param name="value">The maximum archive entries.</param>
    internal void SetMaxArchiveEntries(string value) => MaxArchiveEntries = value;

    /// <summary>
    /// Sets the maximum archive size in decimal megabytes.
    /// </summary>
    /// <param name="value">The maximum archive size.</param>
    internal void SetMaxArchiveMegabytes(string value) => MaxArchiveMegabytes = value;

    /// <summary>
    /// Sets the maximum archive compression ratio.
    /// </summary>
    /// <param name="value">The maximum archive compression ratio.</param>
    internal void SetMaxArchiveRatio(string value) => MaxArchiveRatio = value;

    /// <summary>
    /// Sets the scan timeout in seconds.
    /// </summary>
    /// <param name="value">The timeout in seconds.</param>
    internal void SetTimeoutSeconds(string value) => TimeoutSeconds = value;

    /// <summary>
    /// Builds the command-line preview for the current scan request.
    /// </summary>
    /// <returns>The display-ready command line.</returns>
    internal string BuildCommandLinePreview()
    {
        return TryBuildArguments(out List<string> arguments, out string error)
            ? string.Concat("picket ", JoinArguments(arguments))
            : string.Concat("Cannot build command: ", error);
    }

    /// <summary>
    /// Builds the `picket scan` argument list for the current scan request.
    /// </summary>
    /// <param name="arguments">The built arguments.</param>
    /// <param name="error">The validation error when the request is invalid.</param>
    /// <returns><see langword="true" /> when the arguments were built.</returns>
    internal bool TryBuildArguments(out List<string> arguments, out string error)
    {
        arguments = ["scan"];
        error = string.Empty;

        if (!Validate(out error))
        {
            arguments.Clear();
            return false;
        }

        AddTargetArguments(arguments);
        AddOptionalValue(arguments, "--profile", Profile);
        AddOptionalValue(arguments, "--config", ConfigPath);
        AddOptionalValue(arguments, "--ignore-path", IgnorePath);
        AddFlag(arguments, "--no-ignore", NoIgnore);
        AddFlag(arguments, "--verify", Verify);
        AddFlag(arguments, "--only-verified", OnlyVerified);
        if (!ResultFilter.Equals("all", StringComparison.Ordinal))
        {
            AddOptionalValue(arguments, "--results", ResultFilter);
        }

        if (TargetMode is PicketTuiScanTargetMode.GitHub
            or PicketTuiScanTargetMode.AzureDevOps
            or PicketTuiScanTargetMode.GitLab
            or PicketTuiScanTargetMode.Gitea
            or PicketTuiScanTargetMode.Bitbucket
            or PicketTuiScanTargetMode.S3
            or PicketTuiScanTargetMode.Gcs
            or PicketTuiScanTargetMode.AzureBlob)
        {
            AddFlag(arguments, "--allow-non-public-source-endpoints", AllowNonPublicSourceEndpoints);
            AddFlag(arguments, "--allow-insecure-source-endpoints", AllowInsecureSourceEndpoints);
        }

        AddOptionalValue(arguments, "--report-format", ReportFormat);
        AddOptionalValue(arguments, "--report-path", ReportPath);
        AddOptionalValue(arguments, "--max-target-megabytes", MaxTargetMegabytes);
        AddOptionalValue(arguments, "--max-archive-depth", MaxArchiveDepth);
        AddOptionalValue(arguments, "--max-archive-entries", MaxArchiveEntries);
        AddOptionalValue(arguments, "--max-archive-megabytes", MaxArchiveMegabytes);
        AddOptionalValue(arguments, "--max-archive-ratio", MaxArchiveRatio);
        AddOptionalValue(arguments, "--timeout", TimeoutSeconds);
        if (!string.IsNullOrWhiteSpace(RedactionPercent))
        {
            arguments.Add(string.Concat("--redact=", RedactionPercent.Trim()));
        }

        return true;
    }

    /// <summary>
    /// Runs the current scan request.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel the scan.</param>
    /// <returns>The scanner execution result, or <see langword="null" /> when validation failed.</returns>
    internal ValueTask<PicketTuiScanExecutionResult?> RunAsync(CancellationToken cancellationToken)
    {
        return RunAsync(null, cancellationToken);
    }

    /// <summary>
    /// Runs the current scan request.
    /// </summary>
    /// <param name="outputChanged">The optional callback invoked when live scanner output changes.</param>
    /// <param name="cancellationToken">A token that can cancel the scan.</param>
    /// <returns>The scanner execution result, or <see langword="null" /> when validation failed.</returns>
    internal async ValueTask<PicketTuiScanExecutionResult?> RunAsync(Action? outputChanged, CancellationToken cancellationToken)
    {
        if (IsRunning)
        {
            Status = "Scan already running";
            return null;
        }

        if (!TryBuildArguments(out List<string> arguments, out string error))
        {
            Status = "Scan request is invalid";
            LastMessage = error;
            LastExitCode = null;
            LastStartedAt = null;
            LastCompletedAt = null;
            CaptureMessageOutput("validation", error);
            return null;
        }

        if (!TryEnsureReportDirectory(ReportPath, out string directoryError))
        {
            DateTimeOffset failedAt = DateTimeOffset.UtcNow;
            Status = "Scan failed: could not prepare report path";
            LastMessage = directoryError;
            LastExitCode = 126;
            LastStartedAt = failedAt;
            LastCompletedAt = failedAt;
            return new PicketTuiScanExecutionResult(
                126,
                ReportPath,
                string.Empty,
                directoryError,
                failedAt,
                failedAt);
        }

        IsRunning = true;
        Status = string.Concat("Running: ", BuildTargetDescription());
        LastMessage = BuildCommandLinePreview();
        LastExitCode = null;
        LastStartedAt = DateTimeOffset.UtcNow;
        LastCompletedAt = null;
        ClearCapturedOutput();

        try
        {
            PicketTuiScanExecutionResult result = await _executor.RunAsync(
                arguments,
                ReportPath,
                output =>
                {
                    CaptureOutput(output);
                    outputChanged?.Invoke();
                },
                cancellationToken).ConfigureAwait(false);
            bool reportExists = File.Exists(result.ReportPath);
            LastExitCode = result.ExitCode;
            Status = result.ExitCode switch
            {
                0 when reportExists => "Scan completed: no findings",
                0 => "Scan completed: no findings; report not written",
                1 when reportExists => "Scan completed: findings reported",
                1 => "Scan failed: report was not written",
                _ => string.Concat("Scan failed: exit ", result.ExitCode.ToString(CultureInfo.InvariantCulture)),
            };
            LastMessage = CreateResultMessage(result);
            SetLastRunTiming(result);
            CaptureResultOutputIfEmpty(result);
            return result;
        }
        catch (OperationCanceledException)
        {
            Status = "Scan cancelled";
            LastMessage = "The running scan was cancelled.";
            LastExitCode = 130;
            LastCompletedAt = DateTimeOffset.UtcNow;
            CaptureMessageOutput("status", LastMessage);
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            DateTimeOffset failedAt = DateTimeOffset.UtcNow;
            Status = "Scan failed: could not start scanner";
            LastMessage = ex.Message;
            LastExitCode = 126;
            LastStartedAt ??= failedAt;
            LastCompletedAt = failedAt;
            CaptureMessageOutput("error", ex.Message);
            return new PicketTuiScanExecutionResult(
                126,
                ReportPath,
                string.Empty,
                ex.Message,
                LastStartedAt.GetValueOrDefault(),
                failedAt);
        }
        finally
        {
            IsRunning = false;
        }
    }

    private static string FormatCapturedOutputLine(string stream, string line)
    {
        string trimmed = line.Trim();
        if (trimmed.Length > MaxCapturedOutputLineLength)
        {
            trimmed = string.Concat(trimmed.AsSpan(0, MaxCapturedOutputLineLength - 3), "...");
        }

        return string.Concat(stream, ": ", trimmed);
    }

    private void SetLastRunTiming(PicketTuiScanExecutionResult result)
    {
        LastStartedAt = result.StartedAt;
        LastCompletedAt = result.CompletedAt;
    }

    private void CaptureMessageOutput(string stream, string message)
    {
        ClearCapturedOutput();
        if (!string.IsNullOrWhiteSpace(message))
        {
            AddCapturedOutputLine(FormatCapturedOutputLine(stream, message));
        }
    }

    private void CaptureOutput(PicketTuiScanOutputEvent output)
    {
        AddCapturedOutputLine(FormatCapturedOutputLine(output.Stream, output.Line));
    }

    private void CaptureResultOutputIfEmpty(PicketTuiScanExecutionResult result)
    {
        lock (_outputLock)
        {
            if (_capturedOutputLines.Count != 0)
            {
                return;
            }
        }

        CaptureResultOutput(result);
    }

    private void CaptureResultOutput(PicketTuiScanExecutionResult result)
    {
        ClearCapturedOutput();
        int omittedLineCount = 0;
        AppendCapturedOutput("stderr", result.StandardError, ref omittedLineCount);
        AppendCapturedOutput("stdout", result.StandardOutput, ref omittedLineCount);

        if (omittedLineCount != 0)
        {
            AddCapturedOutputLine(string.Concat("... ", omittedLineCount.ToString(CultureInfo.InvariantCulture), " more output lines"));
        }
    }

    private void AppendCapturedOutput(string stream, string value, ref int omittedLineCount)
    {
        using var reader = new StringReader(value);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (TryAddCapturedOutputLine(FormatCapturedOutputLine(stream, line)))
            {
                continue;
            }

            omittedLineCount++;
        }
    }

    private void ClearCapturedOutput()
    {
        lock (_outputLock)
        {
            _capturedOutputLines.Clear();
        }
    }

    private void AddCapturedOutputLine(string line)
    {
        lock (_outputLock)
        {
            if (_capturedOutputLines.Count < MaxCapturedOutputLines)
            {
                _capturedOutputLines.Add(line);
            }
        }
    }

    private bool TryAddCapturedOutputLine(string line)
    {
        lock (_outputLock)
        {
            if (_capturedOutputLines.Count >= MaxCapturedOutputLines)
            {
                return false;
            }

            _capturedOutputLines.Add(line);
            return true;
        }
    }

    private static bool TryEnsureReportDirectory(string reportPath, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            string? directory = Path.GetDirectoryName(reportPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void AddFlag(List<string> arguments, string name, bool enabled)
    {
        if (enabled)
        {
            arguments.Add(name);
        }
    }

    private static void AddOptionalValue(List<string> arguments, string name, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        arguments.Add(name);
        arguments.Add(value.Trim());
    }

    private static void AddOptionalNonDefaultValue(List<string> arguments, string name, string value, string defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals(defaultValue, StringComparison.Ordinal))
        {
            return;
        }

        arguments.Add(name);
        arguments.Add(value.Trim());
    }

    private static string CreateResultMessage(PicketTuiScanExecutionResult result)
    {
        var builder = new StringBuilder();
        builder.Append("Exit ");
        builder.Append(result.ExitCode.ToString(CultureInfo.InvariantCulture));
        builder.Append(" in ");
        builder.Append(result.Elapsed.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture));
        builder.Append("s. Report: ");
        builder.Append(result.ReportPath);

        string diagnostic = FirstNonEmptyLine(result.StandardError, result.StandardOutput);
        if (diagnostic.Length != 0)
        {
            builder.Append(" Message: ");
            builder.Append(diagnostic);
        }

        return builder.ToString();
    }

    private static string FirstNonEmptyLine(string first, string second)
    {
        string line = FirstNonEmptyLine(first);
        return line.Length == 0 ? FirstNonEmptyLine(second) : line;
    }

    private static string FirstNonEmptyLine(string value)
    {
        using var reader = new StringReader(value);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                return line.Trim();
            }
        }

        return string.Empty;
    }

    private static string GetDefaultReportPath(string reportFormat)
    {
        return reportFormat.Equals("jsonl", StringComparison.Ordinal)
            ? DefaultReportPath
            : string.Concat("picket-results/picket-tui.", reportFormat);
    }

    private static int IndexOf(string[] values, string value)
    {
        for (int i = 0; i < values.Length; i++)
        {
            if (values[i].Equals(value, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return 0;
    }

    private static string JoinArguments(List<string> arguments)
    {
        var builder = new StringBuilder();
        for (int i = 0; i < arguments.Count; i++)
        {
            if (i != 0)
            {
                builder.Append(' ');
            }

            builder.Append(QuoteArgument(arguments[i]));
        }

        return builder.ToString();
    }

    private static string QuoteArgument(string argument)
    {
        return argument.IndexOfAny(s_argumentQuoteCharacters) < 0
            ? argument
            : string.Concat('"', argument.Replace("\"", "\\\"", StringComparison.Ordinal), '"');
    }

    private void AddTargetArguments(List<string> arguments)
    {
        switch (TargetMode)
        {
            case PicketTuiScanTargetMode.Local:
                arguments.Add(LocalPath.Trim());
                break;
            case PicketTuiScanTargetMode.DockerArchive:
                AddOptionalValue(arguments, "--docker-archive", DockerArchivePath);
                break;
            case PicketTuiScanTargetMode.OciArchive:
                AddOptionalValue(arguments, "--oci-archive", OciArchivePath);
                break;
            case PicketTuiScanTargetMode.GitHub:
                AddOptionalValue(arguments, "--github-repository", GitHubRepository);
                AddOptionalValue(arguments, "--github-organization", GitHubOrganization);
                AddOptionalValue(arguments, "--github-user", GitHubUser);
                AddOptionalNonDefaultValue(arguments, "--github-repository-type", GitHubRepositoryType, "all");
                AddOptionalValue(arguments, "--github-gist", GitHubGist);
                AddFlag(arguments, "--github-gists", IncludeGitHubGists);
                AddOptionalValue(arguments, "--github-user-gists", GitHubUserGists);
                AddOptionalValue(arguments, "--github-ref", GitHubRef);
                AddOptionalValue(arguments, "--github-pull-request", GitHubPullRequest);
                AddOptionalValue(arguments, "--github-token-env", GitHubTokenEnvironmentVariable);
                AddFlag(arguments, "--github-include-issues", IncludeGitHubIssues);
                AddOptionalNonDefaultValue(arguments, "--github-issue-state", GitHubIssueState, "all");
                AddFlag(arguments, "--github-include-releases", IncludeGitHubReleases);
                AddFlag(arguments, "--github-include-actions-artifacts", IncludeGitHubActionsArtifacts);
                AddOptionalValue(arguments, "--github-source-api-endpoint", GitHubSourceApiEndpoint);
                break;
            case PicketTuiScanTargetMode.AzureDevOps:
                AddOptionalValue(arguments, "--azure-devops-endpoint", AzureDevOpsEndpoint);
                AddOptionalValue(arguments, "--azure-devops-organization", AzureDevOpsOrganization);
                AddOptionalNonDefaultValue(arguments, "--azure-devops-token-kind", AzureDevOpsTokenKind, "pat");
                AddOptionalValue(arguments, "--azure-devops-project", AzureDevOpsProject);
                AddOptionalValue(arguments, "--azure-devops-repository", AzureDevOpsRepository);
                AddOptionalValue(arguments, "--azure-devops-branch", AzureDevOpsBranch);
                AddOptionalValue(arguments, "--azure-devops-pull-request", AzureDevOpsPullRequest);
                AddOptionalValue(arguments, "--azure-devops-token-env", AzureDevOpsTokenEnvironmentVariable);
                AddOptionalValue(arguments, "--azure-devops-build-id", AzureDevOpsBuildId);
                AddOptionalValue(arguments, "--azure-devops-release-id", AzureDevOpsReleaseId);
                AddFlag(arguments, "--azure-devops-include-wikis", IncludeAzureDevOpsWikis);
                AddFlag(arguments, "--azure-devops-include-artifacts", IncludeAzureDevOpsArtifacts);
                AddFlag(arguments, "--azure-devops-include-logs", IncludeAzureDevOpsLogs);
                AddFlag(arguments, "--azure-devops-include-release-artifacts", IncludeAzureDevOpsReleaseArtifacts);
                AddOptionalValue(arguments, "--azure-devops-max-artifact-megabytes", AzureDevOpsMaxArtifactMegabytes);
                AddOptionalValue(arguments, "--azure-devops-max-log-megabytes", AzureDevOpsMaxLogMegabytes);
                break;
            case PicketTuiScanTargetMode.GitLab:
                AddOptionalValue(arguments, "--gitlab-project", GitLabProject);
                AddOptionalValue(arguments, "--gitlab-group", GitLabGroup);
                AddOptionalValue(arguments, "--gitlab-ref", GitLabRef);
                AddOptionalValue(arguments, "--gitlab-merge-request", GitLabMergeRequest);
                AddOptionalValue(arguments, "--gitlab-pipeline-id", GitLabPipelineId);
                AddFlag(arguments, "--gitlab-include-subgroups", IncludeGitLabSubgroups);
                AddFlag(arguments, "--gitlab-include-snippets", IncludeGitLabSnippets);
                AddFlag(arguments, "--gitlab-include-job-artifacts", IncludeGitLabJobArtifacts);
                AddFlag(arguments, "--gitlab-include-job-logs", IncludeGitLabJobLogs);
                AddFlag(arguments, "--gitlab-include-packages", IncludeGitLabPackages);
                AddOptionalValue(arguments, "--gitlab-token-env", GitLabTokenEnvironmentVariable);
                AddOptionalValue(arguments, "--gitlab-api-endpoint", GitLabApiEndpoint);
                break;
            case PicketTuiScanTargetMode.Gitea:
                AddOptionalValue(arguments, "--gitea-repository", GiteaRepository);
                AddOptionalValue(arguments, "--gitea-organization", GiteaOrganization);
                AddOptionalValue(arguments, "--gitea-user", GiteaUser);
                AddOptionalValue(arguments, "--gitea-ref", GiteaRef);
                AddOptionalValue(arguments, "--gitea-pull-request", GiteaPullRequest);
                AddFlag(arguments, "--gitea-include-issues", IncludeGiteaIssues);
                AddOptionalNonDefaultValue(arguments, "--gitea-issue-state", GiteaIssueState, "all");
                AddFlag(arguments, "--gitea-include-releases", IncludeGiteaReleases);
                AddFlag(arguments, "--gitea-include-actions-artifacts", IncludeGiteaActionsArtifacts);
                AddOptionalValue(arguments, "--gitea-actions-run-id", GiteaActionsRunId);
                AddOptionalValue(arguments, "--gitea-generic-package-owner", GiteaGenericPackageOwner);
                AddOptionalValue(arguments, "--gitea-generic-package-name", GiteaGenericPackageName);
                AddOptionalValue(arguments, "--gitea-generic-package-version", GiteaGenericPackageVersion);
                AddOptionalValue(arguments, "--gitea-generic-package-file", GiteaGenericPackageFile);
                AddOptionalValue(arguments, "--gitea-token-env", GiteaTokenEnvironmentVariable);
                AddOptionalValue(arguments, "--gitea-api-endpoint", GiteaApiEndpoint);
                break;
            case PicketTuiScanTargetMode.Bitbucket:
                AddOptionalValue(arguments, "--bitbucket-repository", BitbucketRepository);
                AddOptionalValue(arguments, "--bitbucket-workspace", BitbucketWorkspace);
                AddOptionalValue(arguments, "--bitbucket-project", BitbucketProject);
                AddOptionalValue(arguments, "--bitbucket-ref", BitbucketRef);
                AddOptionalValue(arguments, "--bitbucket-pull-request", BitbucketPullRequest);
                AddFlag(arguments, "--bitbucket-include-downloads", IncludeBitbucketDownloads);
                AddOptionalValue(arguments, "--bitbucket-pipeline-id", BitbucketPipelineId);
                AddFlag(arguments, "--bitbucket-include-pipeline-logs", IncludeBitbucketPipelineLogs);
                AddFlag(arguments, "--bitbucket-include-snippets", IncludeBitbucketSnippets);
                AddOptionalValue(arguments, "--bitbucket-token-env", BitbucketTokenEnvironmentVariable);
                AddOptionalValue(arguments, "--bitbucket-username-env", BitbucketUsernameEnvironmentVariable);
                AddOptionalNonDefaultValue(arguments, "--bitbucket-token-kind", BitbucketTokenKind, "bearer");
                AddOptionalValue(arguments, "--bitbucket-api-endpoint", BitbucketApiEndpoint);
                break;
            case PicketTuiScanTargetMode.S3:
                AddOptionalValue(arguments, "--s3-bucket", S3Bucket);
                AddOptionalValue(arguments, "--s3-region", S3Region);
                AddOptionalValue(arguments, "--s3-endpoint", S3Endpoint);
                AddOptionalValue(arguments, "--s3-prefix", S3Prefix);
                AddOptionalValue(arguments, "--s3-access-key-id-env", S3AccessKeyIdEnvironmentVariable);
                AddOptionalValue(arguments, "--s3-secret-access-key-env", S3SecretAccessKeyEnvironmentVariable);
                AddOptionalValue(arguments, "--s3-session-token-env", S3SessionTokenEnvironmentVariable);
                break;
            case PicketTuiScanTargetMode.Gcs:
                AddOptionalValue(arguments, "--gcs-bucket", GcsBucket);
                AddOptionalValue(arguments, "--gcs-endpoint", GcsEndpoint);
                AddOptionalValue(arguments, "--gcs-prefix", GcsPrefix);
                AddOptionalValue(arguments, "--gcs-token-env", GcsTokenEnvironmentVariable);
                AddOptionalValue(arguments, "--gcs-user-project", GcsUserProject);
                break;
            case PicketTuiScanTargetMode.AzureBlob:
                AddOptionalValue(arguments, "--azure-blob-endpoint", AzureBlobEndpoint);
                AddOptionalValue(arguments, "--azure-blob-container", AzureBlobContainer);
                AddOptionalValue(arguments, "--azure-blob-prefix", AzureBlobPrefix);
                AddOptionalValue(arguments, "--azure-blob-token-env", AzureBlobTokenEnvironmentVariable);
                AddOptionalNonDefaultValue(arguments, "--azure-blob-token-kind", AzureBlobTokenKind, "bearer");
                break;
        }
    }

    private string BuildTargetDescription()
    {
        return TargetMode switch
        {
            PicketTuiScanTargetMode.Local => string.Concat("local ", LocalPath),
            PicketTuiScanTargetMode.DockerArchive => string.Concat("Docker archive ", FirstConfigured(DockerArchivePath, string.Empty, string.Empty)),
            PicketTuiScanTargetMode.OciArchive => string.Concat("OCI archive ", FirstConfigured(OciArchivePath, string.Empty, string.Empty)),
            PicketTuiScanTargetMode.GitHub => string.Concat("GitHub ", FirstConfigured(GitHubRepository, GitHubOrganization, GitHubUser)),
            PicketTuiScanTargetMode.AzureDevOps => string.Concat("Azure DevOps ", FirstConfigured(AzureDevOpsRepository, AzureDevOpsProject, AzureDevOpsOrganization)),
            PicketTuiScanTargetMode.GitLab => string.Concat("GitLab ", FirstConfigured(GitLabProject, GitLabGroup, string.Empty)),
            PicketTuiScanTargetMode.Gitea => string.Concat("Gitea ", FirstConfigured(GiteaRepository, GiteaOrganization, GiteaUser)),
            PicketTuiScanTargetMode.Bitbucket => string.Concat("Bitbucket ", FirstConfigured(BitbucketRepository, BitbucketWorkspace, BitbucketProject)),
            PicketTuiScanTargetMode.S3 => string.Concat("S3 ", FirstConfigured(S3Bucket, S3Prefix, S3Endpoint)),
            PicketTuiScanTargetMode.Gcs => string.Concat("GCS ", FirstConfigured(GcsBucket, GcsPrefix, GcsEndpoint)),
            PicketTuiScanTargetMode.AzureBlob => string.Concat("Azure Blob ", FirstConfigured(AzureBlobContainer, AzureBlobPrefix, AzureBlobEndpoint)),
            _ => TargetMode.ToString(),
        };
    }

    private static string FirstConfigured(string first, string second, string third)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }

        if (!string.IsNullOrWhiteSpace(second))
        {
            return second;
        }

        return string.IsNullOrWhiteSpace(third) ? "target" : third;
    }

    private bool Validate(out string error)
    {
        error = string.Empty;
        if (TargetMode == PicketTuiScanTargetMode.Local && string.IsNullOrWhiteSpace(LocalPath))
        {
            error = "Local scans require a path.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.DockerArchive && string.IsNullOrWhiteSpace(DockerArchivePath))
        {
            error = "Docker archive scans require an archive path.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.OciArchive && string.IsNullOrWhiteSpace(OciArchivePath))
        {
            error = "OCI archive scans require an archive path.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.S3 && !ValidateS3(out error))
        {
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.Gcs && !ValidateGcs(out error))
        {
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.AzureBlob && !ValidateAzureBlob(out error))
        {
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.GitHub && CountGitHubSourceSelectors() != 1)
        {
            error = "GitHub scans require exactly one repository, organization, user, gist, authenticated-gists, or user-gists selector.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.AzureDevOps
            && string.IsNullOrWhiteSpace(AzureDevOpsOrganization)
            && string.IsNullOrWhiteSpace(AzureDevOpsProject)
            && string.IsNullOrWhiteSpace(AzureDevOpsRepository))
        {
            error = "Azure DevOps scans require an organization, project, or repository selector.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.GitLab && CountGitLabSourceSelectors() != 1)
        {
            error = "GitLab scans require exactly one project or group selector.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.GitLab
            && !string.IsNullOrWhiteSpace(GitLabGroup)
            && !string.IsNullOrWhiteSpace(GitLabMergeRequest))
        {
            error = "--gitlab-merge-request requires a project selector.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.GitLab
            && !string.IsNullOrWhiteSpace(GitLabGroup)
            && !string.IsNullOrWhiteSpace(GitLabPipelineId))
        {
            error = "--gitlab-pipeline-id requires a project selector.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.GitLab
            && !string.IsNullOrWhiteSpace(GitLabPipelineId)
            && !IncludeGitLabJobArtifacts
            && !IncludeGitLabJobLogs)
        {
            error = "--gitlab-pipeline-id requires GitLab job logs or artifacts.";
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.Gitea && !ValidateGitea(out error))
        {
            return false;
        }

        if (TargetMode == PicketTuiScanTargetMode.Bitbucket && !ValidateBitbucket(out error))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(Profile))
        {
            error = "Profile is required.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(ReportPath))
        {
            error = "Report path is required.";
            return false;
        }

        return ValidateOptionalNonNegativeInteger(RedactionPercent, "--redact", min: 0, max: 100, out error)
            && ValidateOptionalNonNegativeInteger(MaxTargetMegabytes, "--max-target-megabytes", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(MaxArchiveDepth, "--max-archive-depth", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(MaxArchiveEntries, "--max-archive-entries", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(MaxArchiveMegabytes, "--max-archive-megabytes", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(MaxArchiveRatio, "--max-archive-ratio", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(TimeoutSeconds, "--timeout", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(AzureDevOpsBuildId, "--azure-devops-build-id", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(AzureDevOpsReleaseId, "--azure-devops-release-id", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(AzureDevOpsMaxArtifactMegabytes, "--azure-devops-max-artifact-megabytes", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(AzureDevOpsMaxLogMegabytes, "--azure-devops-max-log-megabytes", min: 0, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(GitLabMergeRequest, "--gitlab-merge-request", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(GitLabPipelineId, "--gitlab-pipeline-id", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(GiteaPullRequest, "--gitea-pull-request", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(GiteaActionsRunId, "--gitea-actions-run-id", min: 1, max: int.MaxValue, out error)
            && ValidateOptionalNonNegativeInteger(BitbucketPullRequest, "--bitbucket-pull-request", min: 1, max: int.MaxValue, out error);
    }

    private bool ValidateS3(out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(S3Bucket))
        {
            error = "S3 scans require a bucket.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(S3Region))
        {
            error = "S3 scans require a region.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(S3AccessKeyIdEnvironmentVariable))
        {
            error = "S3 scans require an access key ID environment variable.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(S3SecretAccessKeyEnvironmentVariable))
        {
            error = "S3 scans require a secret access key environment variable.";
            return false;
        }

        return true;
    }

    private bool ValidateGcs(out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(GcsBucket))
        {
            error = "GCS scans require a bucket.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(GcsTokenEnvironmentVariable))
        {
            error = "GCS scans require a token environment variable.";
            return false;
        }

        return true;
    }

    private bool ValidateAzureBlob(out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(AzureBlobEndpoint))
        {
            error = "Azure Blob scans require an endpoint.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(AzureBlobContainer))
        {
            error = "Azure Blob scans require a container.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(AzureBlobTokenEnvironmentVariable))
        {
            error = "Azure Blob scans require a token environment variable.";
            return false;
        }

        return true;
    }

    private bool ValidateGitea(out string error)
    {
        error = string.Empty;
        bool genericPackageCoordinateSpecified = !string.IsNullOrWhiteSpace(GiteaGenericPackageName)
            || !string.IsNullOrWhiteSpace(GiteaGenericPackageVersion)
            || !string.IsNullOrWhiteSpace(GiteaGenericPackageFile);
        bool genericPackageSpecified = !string.IsNullOrWhiteSpace(GiteaGenericPackageOwner)
            || genericPackageCoordinateSpecified;

        if (CountGiteaSourceSelectors(genericPackageSpecified) != 1)
        {
            error = "Gitea scans require exactly one repository, organization, user, or generic-package selector.";
            return false;
        }

        if (genericPackageCoordinateSpecified
            && (string.IsNullOrWhiteSpace(GiteaGenericPackageOwner)
                || string.IsNullOrWhiteSpace(GiteaGenericPackageName)
                || string.IsNullOrWhiteSpace(GiteaGenericPackageVersion)
                || string.IsNullOrWhiteSpace(GiteaGenericPackageFile)))
        {
            error = "Gitea generic package scans use either only the package owner or all four generic-package fields.";
            return false;
        }

        if (genericPackageSpecified
            && (!string.IsNullOrWhiteSpace(GiteaRef)
                || !string.IsNullOrWhiteSpace(GiteaPullRequest)
                || IncludeGiteaIssues
                || IncludeGiteaReleases
                || IncludeGiteaActionsArtifacts
                || !string.IsNullOrWhiteSpace(GiteaActionsRunId)))
        {
            error = "Gitea generic package scans cannot be combined with refs, pull requests, issues, releases, or Actions artifacts.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(GiteaPullRequest)
            && string.IsNullOrWhiteSpace(GiteaRepository))
        {
            error = "--gitea-pull-request requires a repository selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(GiteaPullRequest)
            && !string.IsNullOrWhiteSpace(GiteaRef))
        {
            error = "Gitea scans accept either --gitea-ref or --gitea-pull-request, not both.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(GiteaPullRequest)
            && (IncludeGiteaIssues || IncludeGiteaReleases || IncludeGiteaActionsArtifacts))
        {
            error = "Gitea pull request scans cannot be combined with issues, releases, or Actions artifacts.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(GiteaActionsRunId)
            && !IncludeGiteaActionsArtifacts)
        {
            error = "--gitea-actions-run-id requires --gitea-include-actions-artifacts.";
            return false;
        }

        return true;
    }

    private bool ValidateBitbucket(out string error)
    {
        error = string.Empty;
        bool hasRepository = !string.IsNullOrWhiteSpace(BitbucketRepository);
        bool hasWorkspace = !string.IsNullOrWhiteSpace(BitbucketWorkspace);
        if (hasRepository == hasWorkspace)
        {
            error = "Bitbucket scans require exactly one repository or workspace selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPullRequest)
            && !hasRepository)
        {
            error = "--bitbucket-pull-request requires a repository selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPullRequest)
            && !string.IsNullOrWhiteSpace(BitbucketRef))
        {
            error = "Bitbucket scans accept either --bitbucket-ref or --bitbucket-pull-request, not both.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPullRequest)
            && IncludeBitbucketDownloads)
        {
            error = "Bitbucket pull request scans cannot be combined with download artifacts.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPullRequest)
            && !string.IsNullOrWhiteSpace(BitbucketPipelineId))
        {
            error = "Bitbucket pull request scans cannot be combined with pipeline logs.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPipelineId)
            && !hasRepository)
        {
            error = "--bitbucket-pipeline-id requires a repository selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketPipelineId)
            && !IncludeBitbucketPipelineLogs)
        {
            error = "--bitbucket-pipeline-id requires --bitbucket-include-pipeline-logs.";
            return false;
        }

        if (IncludeBitbucketPipelineLogs
            && string.IsNullOrWhiteSpace(BitbucketPipelineId))
        {
            error = "--bitbucket-include-pipeline-logs requires --bitbucket-pipeline-id.";
            return false;
        }

        if (IncludeBitbucketSnippets && !hasWorkspace)
        {
            error = "--bitbucket-include-snippets requires a workspace selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketProject) && !hasWorkspace)
        {
            error = "--bitbucket-project requires a workspace selector.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(BitbucketProject) && IncludeBitbucketSnippets)
        {
            error = "Bitbucket project scans cannot be combined with workspace snippets.";
            return false;
        }

        return true;
    }

    private static bool ValidateOptionalNonNegativeInteger(string value, string option, int min, int max, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed)
            || parsed < min
            || parsed > max)
        {
            error = string.Concat(option, " requires an integer from ", min.ToString(CultureInfo.InvariantCulture), " through ", max.ToString(CultureInfo.InvariantCulture), ".");
            return false;
        }

        return true;
    }

    private int CountGitHubSourceSelectors()
    {
        int count = 0;
        if (!string.IsNullOrWhiteSpace(GitHubRepository))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GitHubOrganization))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GitHubUser))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GitHubGist))
        {
            count++;
        }

        if (IncludeGitHubGists)
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GitHubUserGists))
        {
            count++;
        }

        return count;
    }

    private int CountGitLabSourceSelectors()
    {
        int count = 0;
        if (!string.IsNullOrWhiteSpace(GitLabProject))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GitLabGroup))
        {
            count++;
        }

        return count;
    }

    private int CountGiteaSourceSelectors(bool genericPackageSpecified)
    {
        int count = 0;
        if (!string.IsNullOrWhiteSpace(GiteaRepository))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GiteaOrganization))
        {
            count++;
        }

        if (!string.IsNullOrWhiteSpace(GiteaUser))
        {
            count++;
        }

        if (genericPackageSpecified)
        {
            count++;
        }

        return count;
    }
}
