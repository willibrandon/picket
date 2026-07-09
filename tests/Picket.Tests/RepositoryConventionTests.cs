using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Picket.Tests;

/// <summary>
/// Tests repository-level source conventions.
/// </summary>
[TestClass]
public sealed partial class RepositoryConventionTests
{
    private const string MacOsStripSymbolsCondition = "'$(RuntimeIdentifier)' == 'osx-arm64' or '$(RuntimeIdentifier)' == 'osx-x64'";
    private const string NonMacOsStripSymbolsCondition = "'$(RuntimeIdentifier)' != 'osx-arm64' and '$(RuntimeIdentifier)' != 'osx-x64'";

    private static readonly string[] s_fileBasedAppDirectories = ["scripts", ".github/actions"];
    private static readonly string[] s_portableTextRoots = ["AGENTS.md", "docs", "docs-site/src/content/docs", "scripts", ".github", "azure-devops", "src", "tests"];
    private static readonly string[] s_remoteSourceClientFiles =
    [
        "src/Picket.Sources/AzureDevOpsSourceClient.cs",
        "src/Picket.Sources/BitbucketSourceClient.cs",
        "src/Picket.Sources/GcsSourceClient.cs",
        "src/Picket.Sources/GiteaSourceClient.cs",
        "src/Picket.Sources/GitHubSourceClient.cs",
        "src/Picket.Sources/GitLabSourceClient.cs",
    ];
    private static readonly string[] s_remoteXmlSourceClientFiles =
    [
        "src/Picket.Sources/AzureBlobSourceClient.cs",
        "src/Picket.Sources/S3SourceClient.cs",
    ];
    private static readonly string[] s_sourceEndpointGuardWiringFiles =
    [
        "src/Picket.Cli/Program.AzureBlob.cs",
        "src/Picket.Cli/Program.Bitbucket.cs",
        "src/Picket.Cli/Program.Gcs.cs",
        "src/Picket.Cli/Program.Gitea.cs",
        "src/Picket.Cli/Program.GitHub.cs",
        "src/Picket.Cli/Program.GitLab.cs",
        "src/Picket.Cli/Program.S3.cs",
    ];
    private static readonly SemaphoreSlim s_fileBasedAppBuildLock = new(1, 1);
    private static readonly Regex s_typeDeclarationPattern = CreateTypeDeclarationPattern();

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that each source file declares at most one explicit type.
    /// </summary>
    [TestMethod]
    public void SourceFilesDeclareAtMostOneExplicitType()
    {
        string root = FindRepositoryRoot();
        List<string> violations = [];

        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            if (!IsRepositorySourceFile(root, file))
            {
                continue;
            }

            int typeCount = s_typeDeclarationPattern.Count(File.ReadAllText(file));
            if (typeCount > 1)
            {
                violations.Add(Path.GetRelativePath(root, file));
            }
        }

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that source files sort using directives as a single alphabetic block.
    /// </summary>
    [TestMethod]
    public void SourceFilesSortUsingsAlphabetically()
    {
        string root = FindRepositoryRoot();
        List<string> violations = [];

        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            if (!IsRepositoryCSharpFile(root, file))
            {
                continue;
            }

            string relative = Path.GetRelativePath(root, file);
            string[] lines = File.ReadAllLines(file);
            List<int> usingLineIndexes = [];
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith("using ", StringComparison.Ordinal))
                {
                    usingLineIndexes.Add(i);
                }
            }

            if (usingLineIndexes.Count == 0)
            {
                continue;
            }

            int firstUsingLineIndex = usingLineIndexes[0];
            int lastUsingLineIndex = usingLineIndexes[^1];
            for (int i = firstUsingLineIndex; i <= lastUsingLineIndex; i++)
            {
                if (lines[i].Length == 0)
                {
                    violations.Add($"{relative}:{i + 1}: using directives must not be separated by blank lines");
                    continue;
                }

                if (!lines[i].StartsWith("using ", StringComparison.Ordinal))
                {
                    violations.Add($"{relative}:{i + 1}: using directives must be contiguous");
                }
            }

            string[] actual = [.. usingLineIndexes.Select(index => lines[index])];
            string[] expected = [.. actual.OrderBy(GetUsingSortKey, StringComparer.Ordinal)];
            if (!actual.SequenceEqual(expected))
            {
                violations.Add($"{relative}:{firstUsingLineIndex + 1}: using directives must be sorted alphabetically");
            }
        }

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that public source does not retain user-facing placeholder implementation messages.
    /// </summary>
    [TestMethod]
    public void SourceFilesDoNotExposePlaceholderImplementationMessages()
    {
        string root = FindRepositoryRoot();
        List<string> violations = [];

        foreach (string file in Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories))
        {
            if (!IsRepositoryCSharpFile(root, file))
            {
                continue;
            }

            string text = File.ReadAllText(file);
            if (text.Contains("not implemented yet", StringComparison.OrdinalIgnoreCase))
            {
                violations.Add(Path.GetRelativePath(root, file));
            }
        }

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that the GitHub Action metadata exposes the security scanner contract.
    /// </summary>
    [TestMethod]
    public void GitHubActionMetadataDocumentsSecurityContract()
    {
        string action = ReadRepositoryFile("action.yml");

        Assert.Contains("upload-sarif", action);
        Assert.Contains("fail-on", action);
        Assert.Contains("summary", action);
        Assert.Contains("results", action);
        Assert.Contains("only-verified", action);
        Assert.Contains("annotations", action);
        Assert.Contains("annotation-limit", action);
        Assert.Contains("cache-mode", action);
        Assert.Contains("cache-path", action);
        Assert.Contains("redact", action);
        Assert.Contains("timeout", action);
        Assert.Contains("max-archive-depth", action);
        Assert.Contains("max-archive-entries", action);
        Assert.Contains("max-archive-megabytes", action);
        Assert.Contains("max-archive-ratio", action);
        Assert.Contains("actions/cache/restore", action);
        Assert.Contains("actions/cache/save", action);
        Assert.Contains("github/codeql-action/upload-sarif", action);
        Assert.Contains("actions/setup-dotnet", action);
        Assert.Contains("run-picket.cs", action);
        Assert.Contains("dotnet build", action);
        Assert.Contains("dotnet run --file", action);
        Assert.Contains("--no-build", action);
    }

    /// <summary>
    /// Verifies that the GitHub Action helper emits stable outputs without requiring raw secret logs.
    /// </summary>
    [TestMethod]
    public void GitHubActionHelperDefinesStableOutputs()
    {
        string helper = ReadRepositoryFile(".github/actions/run-picket.cs");
        string readme = ReadRepositoryFile(".github/actions/README.md");

        Assert.Contains("GITHUB_OUTPUT", helper);
        Assert.Contains("GITHUB_STEP_SUMMARY", helper);
        Assert.Contains("picket.sarif", helper);
        Assert.Contains("picket.jsonl", helper);
        Assert.Contains("--redact={redact}", helper);
        Assert.Contains("--cache-dir", helper);
        Assert.Contains("--cache-mode", helper);
        Assert.Contains("PICKET_CACHE_MODE", helper);
        Assert.Contains("PICKET_SUMMARY", helper);
        Assert.Contains("summary must be true or false", helper);
        Assert.Contains("PICKET_RESULTS", helper);
        Assert.Contains("PICKET_ONLY_VERIFIED", helper);
        Assert.Contains("--results", helper);
        Assert.Contains("--only-verified", helper);
        Assert.Contains("--max-target-megabytes", helper);
        Assert.Contains("--timeout", helper);
        Assert.Contains("--max-archive-depth", helper);
        Assert.Contains("--max-archive-entries", helper);
        Assert.Contains("--max-archive-megabytes", helper);
        Assert.Contains("--max-archive-ratio", helper);
        Assert.Contains("JsonNode.Parse", helper);
        Assert.Contains("::warning", helper);
        Assert.Contains("PICKET_ANNOTATIONS", helper);
        Assert.Contains("PICKET_ANNOTATION_LIMIT", helper);
        Assert.Contains("GetFindingBreakdownSummaryLines", helper);
        Assert.Contains("Findings by rule", helper);
        Assert.Contains("Findings by file", helper);
        Assert.Contains("ConvertToMarkdownCell", helper);
        Assert.DoesNotContain("finding.secret", helper);
        Assert.DoesNotContain("finding.match", helper);
        Assert.DoesNotContain("finding.line", helper);
        Assert.Contains("should-fail", helper);
        Assert.Contains("failure-code", helper);
        Assert.Contains("annotations", helper);
        Assert.Contains("dotnet build", readme);
        Assert.Contains("dotnet run --file", readme);
        Assert.Contains("--no-build", readme);
        Assert.Contains("Directory.Build.props", readme);
        Assert.Contains("GITHUB_OUTPUT", readme);
        Assert.Contains("GITHUB_STEP_SUMMARY", readme);
        Assert.Contains("must not print raw", readme);
    }

    /// <summary>
    /// Verifies that the GitHub Action documentation covers permissions, redaction, caching, outputs, and fail modes.
    /// </summary>
    [TestMethod]
    public void GitHubActionDocumentationCoversOperationalContract()
    {
        string documentation = ReadRepositoryFile("docs/ACTION.md");

        Assert.Contains("contents: read", documentation);
        Assert.Contains("security-events: write", documentation);
        Assert.Contains("fail-on: findings", documentation);
        Assert.Contains("fail-on: errors", documentation);
        Assert.Contains("fail-on: never", documentation);
        Assert.Contains("summary", documentation);
        Assert.Contains("only-verified", documentation);
        Assert.Contains("results", documentation);
        Assert.Contains("annotation-limit", documentation);
        Assert.Contains("cache-mode", documentation);
        Assert.Contains("secret-hash-only", documentation);
        Assert.Contains("Annotations", documentation);
        Assert.Contains("redact: 0", documentation);
        Assert.Contains("upload-sarif", documentation);
        Assert.Contains("cache-path", documentation);
        Assert.Contains("timeout", documentation);
        Assert.Contains("max-archive-depth", documentation);
        Assert.Contains("max-archive-entries", documentation);
        Assert.Contains("max-archive-megabytes", documentation);
        Assert.Contains("max-archive-ratio", documentation);
        Assert.Contains("actions/cache/restore", documentation);
        Assert.Contains("actions/cache/save", documentation);
        Assert.Contains("picket.sarif", documentation);
        Assert.Contains("picket.jsonl", documentation);
        Assert.Contains("breakdowns by rule and by file", documentation);
        Assert.Contains("CI Matrix Scan", documentation);
        Assert.Contains("repository root on every CI runner", documentation);
    }

    /// <summary>
    /// Verifies that named Native AOT publish profiles match the release design contract.
    /// </summary>
    [TestMethod]
    public void CliPublishProfilesMatchReleaseContract()
    {
        XElement cliProject = ReadProjectFile("src/Picket.Cli/Picket.Cli.csproj");
        XElement tuiProject = ReadProjectFile("src/Picket.Tui/Picket.Tui.csproj");
        XElement tuiCliProject = ReadProjectFile("src/Picket.Tui.Cli/Picket.Tui.Cli.csproj");
        XElement speed = ReadPublishProfile("release-speed");
        XElement minSize = ReadPublishProfile("release-minsize");
        XElement diagnostics = ReadPublishProfile("release-diagnostics");
        XElement tuiSpeed = ReadPublishProfile("src/Picket.Tui.Cli", "release-speed");
        XElement tuiMinSize = ReadPublishProfile("src/Picket.Tui.Cli", "release-minsize");
        XElement tuiDiagnostics = ReadPublishProfile("src/Picket.Tui.Cli", "release-diagnostics");

        AssertProjectProperty(cliProject, "VerifyReferenceTrimCompatibility", "true");
        AssertProjectProperty(cliProject, "VerifyReferenceAotCompatibility", "true");
        AssertProjectProperty(cliProject, "TrimmerSingleWarn", "false");
        AssertProjectProperty(tuiProject, "IsAotCompatible", "true");
        AssertProjectProperty(tuiProject, "VerifyReferenceTrimCompatibility", "true");
        AssertProjectProperty(tuiProject, "VerifyReferenceAotCompatibility", "true");
        AssertProjectProperty(tuiCliProject, "PublishAot", "true");
        AssertProjectProperty(tuiCliProject, "IsAotCompatible", "true");
        AssertProjectProperty(tuiCliProject, "VerifyReferenceTrimCompatibility", "true");
        AssertProjectProperty(tuiCliProject, "VerifyReferenceAotCompatibility", "true");
        AssertCommonNativeAotProfile(speed);
        AssertCommonNativeAotProfile(minSize);
        AssertCommonNativeAotProfile(diagnostics);
        AssertCommonNativeAotProfile(tuiSpeed);
        AssertCommonNativeAotProfile(tuiMinSize);
        AssertCommonNativeAotProfile(tuiDiagnostics);
        AssertProfileProperty(speed, "OptimizationPreference", "Speed");
        AssertProfileStripSymbolsExceptMacOs(speed);
        AssertProfileDisablesMacOsNativeDebugSymbols(speed);
        AssertProfileProperty(speed, "DebuggerSupport", "false");
        AssertProfileProperty(minSize, "OptimizationPreference", "Size");
        AssertProfileStripSymbolsExceptMacOs(minSize);
        AssertProfileDisablesMacOsNativeDebugSymbols(minSize);
        AssertProfileProperty(minSize, "DebuggerSupport", "false");
        AssertProfileProperty(minSize, "EventSourceSupport", "false");
        AssertProfileProperty(minSize, "MetricsSupport", "false");
        AssertProfileProperty(minSize, "StackTraceSupport", "false");
        AssertProfileProperty(minSize, "UseSystemResourceKeys", "true");
        AssertProfileProperty(diagnostics, "OptimizationPreference", "Speed");
        AssertProfileProperty(diagnostics, "StripSymbols", "false");
        AssertProfileProperty(diagnostics, "DebuggerSupport", "true");
        AssertProfileProperty(diagnostics, "EventSourceSupport", "true");
        AssertProfileProperty(diagnostics, "MetricsSupport", "true");
        AssertProfileProperty(diagnostics, "StackTraceSupport", "true");
        AssertProfileProperty(tuiSpeed, "OptimizationPreference", "Speed");
        AssertProfileStripSymbolsExceptMacOs(tuiSpeed);
        AssertProfileDisablesMacOsNativeDebugSymbols(tuiSpeed);
        AssertProfileProperty(tuiSpeed, "DebuggerSupport", "false");
        AssertProfileProperty(tuiMinSize, "OptimizationPreference", "Size");
        AssertProfileStripSymbolsExceptMacOs(tuiMinSize);
        AssertProfileDisablesMacOsNativeDebugSymbols(tuiMinSize);
        AssertProfileProperty(tuiMinSize, "DebuggerSupport", "false");
        AssertProfileProperty(tuiMinSize, "EventSourceSupport", "false");
        AssertProfileProperty(tuiMinSize, "MetricsSupport", "false");
        AssertProfileProperty(tuiMinSize, "StackTraceSupport", "false");
        AssertProfileProperty(tuiMinSize, "UseSystemResourceKeys", "true");
        AssertProfileProperty(tuiDiagnostics, "OptimizationPreference", "Speed");
        AssertProfileProperty(tuiDiagnostics, "StripSymbols", "false");
        AssertProfileProperty(tuiDiagnostics, "DebuggerSupport", "true");
        AssertProfileProperty(tuiDiagnostics, "EventSourceSupport", "true");
        AssertProfileProperty(tuiDiagnostics, "MetricsSupport", "true");
        AssertProfileProperty(tuiDiagnostics, "StackTraceSupport", "true");
    }

    /// <summary>
    /// Verifies that release documentation covers the named Native AOT publish profiles.
    /// </summary>
    [TestMethod]
    public void ReleaseDocumentationCoversPublishProfiles()
    {
        string documentation = ReadRepositoryFile("docs/RELEASE.md");

        Assert.Contains("release-speed", documentation);
        Assert.Contains("release-minsize", documentation);
        Assert.Contains("release-diagnostics", documentation);
        Assert.Contains("Picket.Tui.Cli", documentation);
        Assert.Contains("-r win-x64", documentation);
        Assert.Contains("Native AOT", documentation);
        Assert.Contains("must not change scanner findings", documentation);
        Assert.Contains("Release Workflow", documentation);
        Assert.Contains("actions/attest@v4", documentation);
        Assert.Contains("gh attestation verify", documentation);
        Assert.Contains("NUGET_API_KEY", documentation);
    }

    /// <summary>
    /// Verifies that CI packs the public NuGet libraries on every supported runner.
    /// </summary>
    [TestMethod]
    public void CiWorkflowPacksPublicPackages()
    {
        string workflow = ReadRepositoryFile(".github/workflows/ci.yml");
        string documentation = ReadRepositoryFile("docs/RELEASE.md");
        string azureDevOpsPackage = ReadRepositoryFile("azure-devops/package.json");
        string azureDevOpsLock = ReadRepositoryFile("azure-devops/package-lock.json");

        Assert.Contains("Pack public packages", workflow);
        Assert.Contains("Publish Native AOT binaries", workflow);
        Assert.Contains("dotnet publish src/Picket.Cli/Picket.Cli.csproj", workflow);
        Assert.Contains("dotnet publish src/Picket.Tui.Cli/Picket.Tui.Cli.csproj", workflow);
        Assert.Contains("PublishProfile=release-speed", workflow);
        Assert.Contains("${{ matrix.rid }}", workflow);
        Assert.Contains("rid: linux-x64", workflow);
        Assert.Contains("rid: linux-arm64", workflow);
        Assert.Contains("rid: win-x64", workflow);
        Assert.Contains("rid: win-arm64", workflow);
        Assert.Contains("rid: osx-x64", workflow);
        Assert.Contains("rid: osx-arm64", workflow);
        Assert.Contains("ubuntu-24.04-arm", workflow);
        Assert.Contains("windows-11-arm", workflow);
        Assert.Contains("macos-26-intel", workflow);
        Assert.Contains("Picket scan", workflow);
        Assert.Contains("uses: ./", workflow);
        Assert.Contains("path: .", workflow);
        Assert.Contains("setup-dotnet: \"false\"", workflow);
        Assert.Contains("summary: \"true\"", workflow);
        Assert.Contains("annotations: \"false\"", workflow);
        Assert.Contains("Verify Picket scan outputs", workflow);
        Assert.Contains("steps.picket-scan.outputs.findings", workflow);
        Assert.Contains("Picket scan reported no findings.", workflow);
        Assert.Contains("report-directory: ${{ runner.temp }}/picket-scan", workflow);
        Assert.DoesNotContain("if: ${{ matrix.os == 'ubuntu-latest' }}", workflow);
        Assert.DoesNotContain("path: tests/fixtures/github-secret-scanning", workflow);
        Assert.DoesNotContain("Write GitHub Action smoke summary", workflow);
        Assert.Contains("dotnet pack src/Picket.Rules/Picket.Rules.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Engine/Picket.Engine.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Report/Picket.Report.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Security/Picket.Security.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Cli/Picket.Cli.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Tui.Cli/Picket.Tui.Cli.csproj", workflow);
        Assert.Contains("-p:IncludeSymbols=false", workflow);
        Assert.Contains("dotnet pack src/Picket.Cli/Picket.Cli.csproj --configuration Release -p:PublishProfile=release-speed -r ${{ matrix.rid }}", workflow);
        Assert.Contains("dotnet pack src/Picket.Tui.Cli/Picket.Tui.Cli.csproj --configuration Release -p:PublishProfile=release-speed -r ${{ matrix.rid }}", workflow);
        Assert.Contains("Validate Azure DevOps VSIX package", workflow);
        Assert.Contains("npm ci --ignore-scripts --no-audit --no-fund", workflow);
        Assert.Contains("npm exec -- tfx extension create", workflow);
        Assert.DoesNotContain("npx --yes", workflow);
        Assert.Contains("\"tfx-cli\": \"0.23.3\"", azureDevOpsPackage);
        Assert.Contains("\"node_modules/tfx-cli\"", azureDevOpsLock);
        Assert.Contains("--manifest-globs vss-extension.json", workflow);
        Assert.Contains("working-directory: azure-devops", workflow);
        Assert.Contains("--no-build", workflow);
        Assert.Contains("shell: pwsh", workflow);
        Assert.Contains("ubuntu-latest", workflow);
        Assert.Contains("windows-latest", workflow);
        Assert.Contains("macos-26", workflow);
        Assert.Contains("NuGet Package Validation", documentation);
        Assert.Contains("Every CI run packs the public embeddable library packages", documentation);
        Assert.Contains("Every CI run also packs the Native AOT dotnet tool packages", documentation);
        Assert.Contains("cross-platform MSBuild paths", documentation);
        Assert.Contains("Native AOT Publish Validation", documentation);
        Assert.Contains("Every CI run also publishes `picket` and `picket-tui` with `release-speed`", documentation);
        Assert.Contains("normal `dotnet build` is not enough evidence", documentation);
        Assert.Contains("Azure DevOps VSIX Validation", documentation);
        Assert.Contains("CI packages the Azure DevOps Marketplace scaffold", documentation);
        Assert.Contains("CI Picket Scan Validation", documentation);
        Assert.Contains("both `picket.sarif` and `picket.jsonl`", documentation);
    }

    /// <summary>
    /// Verifies that mutable third-party workflow dependencies are pinned or resolved through repository lockfiles.
    /// </summary>
    [TestMethod]
    public void WorkflowsPinThirdPartySetupAndPackagingDependencies()
    {
        const string PnpmActionSetupPinnedRef = "pnpm/action-setup@0ebf47130e4866e96fce0953f49152a61190b271 # v6.0.9";
        string ci = ReadRepositoryFile(".github/workflows/ci.yml");
        string docs = ReadRepositoryFile(".github/workflows/docs.yml");
        string release = ReadRepositoryFile(".github/workflows/release.yml");
        string azureDevOpsLock = ReadRepositoryFile("azure-devops/package-lock.json");

        Assert.Contains(PnpmActionSetupPinnedRef, docs);
        Assert.Contains(PnpmActionSetupPinnedRef, release);
        Assert.DoesNotContain("pnpm/action-setup@v", docs);
        Assert.DoesNotContain("pnpm/action-setup@v", release);
        Assert.DoesNotContain("npx --yes", ci);
        Assert.Contains("npm ci --ignore-scripts --no-audit --no-fund", ci);
        Assert.Contains("npm exec -- tfx extension create", ci);
        Assert.Contains("\"lockfileVersion\": 3", azureDevOpsLock);
        Assert.Contains("\"node_modules/tfx-cli\"", azureDevOpsLock);
    }

    /// <summary>
    /// Verifies that live Azure DevOps source scans stay opt-in and use the dedicated test secret.
    /// </summary>
    [TestMethod]
    public void LiveAzureDevOpsWorkflowIsManualOnly()
    {
        string workflow = ReadRepositoryFile(".github/workflows/live-azure-devops.yml");
        string azureDevOps = ReadRepositoryFile("docs/AZURE_DEVOPS.md");
        string marketplaces = ReadRepositoryFile("docs/MARKETPLACES.md");

        Assert.Contains("workflow_dispatch:", workflow);
        Assert.DoesNotContain("pull_request:", workflow);
        Assert.DoesNotContain("push:", workflow);
        Assert.Contains("AZURE_DEVOPS_TEST_PAT", workflow);
        Assert.Contains("default: picket", workflow);
        Assert.Contains("--azure-devops-endpoint", workflow);
        Assert.Contains("--azure-devops-token-env", workflow);
        Assert.Contains("--redact=100", workflow);
        Assert.Contains("actions/upload-artifact@v7", workflow);
        Assert.DoesNotContain("outputs.report-path", workflow);
        Assert.Contains("Live Azure DevOps", azureDevOps);
        Assert.Contains("https://dev.azure.com/willibrandon/picket", azureDevOps);
        Assert.Contains("AZURE_DEVOPS_TEST_PAT", marketplaces);
        Assert.Contains("manual `Live Azure DevOps` workflow", marketplaces);
    }

    /// <summary>
    /// Verifies that the Azure DevOps task metadata exposes the scanner contract without owning scanner behavior.
    /// </summary>
    [TestMethod]
    public void AzureDevOpsTaskMetadataDocumentsScannerContract()
    {
        using JsonDocument extension = JsonDocument.Parse(ReadRepositoryFile("azure-devops/vss-extension.json"));
        string taskMetadata = ReadRepositoryFile("azure-devops/tasks/PicketScanV1/task.json");
        using JsonDocument task = JsonDocument.Parse(taskMetadata);
        string handler = ReadRepositoryFile("azure-devops/tasks/PicketScanV1/index.js");
        string handlerTests = ReadRepositoryFile("azure-devops/tasks/PicketScanV1/index.test.js");
        string readme = ReadRepositoryFile("azure-devops/README.md");
        string azureDevOps = ReadRepositoryFile("docs/AZURE_DEVOPS.md");
        string workflow = ReadRepositoryFile(".github/workflows/ci.yml");
        string marketplaces = ReadRepositoryFile("docs/MARKETPLACES.md");

        JsonElement extensionRoot = extension.RootElement;
        Assert.AreEqual("picket", extensionRoot.GetProperty("id").GetString());
        Assert.AreEqual("willibrandon", extensionRoot.GetProperty("publisher").GetString());
        Assert.AreEqual("0.1.1", extensionRoot.GetProperty("version").GetString());
        Assert.AreEqual("tasks/PicketScanV1", extensionRoot.GetProperty("contributions")[0].GetProperty("properties").GetProperty("name").GetString());

        JsonElement taskRoot = task.RootElement;
        Assert.AreEqual("PicketScan", taskRoot.GetProperty("name").GetString());
        Assert.AreEqual("Picket scan", taskRoot.GetProperty("friendlyName").GetString());
        Assert.AreEqual(1, taskRoot.GetProperty("version").GetProperty("Major").GetInt32());
        Assert.AreEqual(1, taskRoot.GetProperty("version").GetProperty("Patch").GetInt32());
        Assert.AreEqual("index.js", taskRoot.GetProperty("execution").GetProperty("Node20_1").GetProperty("target").GetString());

        HashSet<string> inputNames = ReadJsonNameSet(taskRoot.GetProperty("inputs"));
        Assert.Contains("target", inputNames);
        Assert.Contains("picketPath", inputNames);
        Assert.Contains("profile", inputNames);
        Assert.Contains("reportFormats", inputNames);
        Assert.Contains("reportDirectory", inputNames);
        Assert.Contains("failOn", inputNames);
        Assert.Contains("baselinePath", inputNames);
        Assert.Contains("redact", inputNames);
        Assert.Contains("cacheMode", inputNames);
        Assert.Contains("azureDevOpsOrganization", inputNames);
        Assert.Contains("azureDevOpsTokenEnv", inputNames);
        Assert.Contains("azureDevOpsIncludeArtifacts", inputNames);
        Assert.Contains("azureDevOpsIncludeReleaseArtifacts", inputNames);
        Assert.Contains("allowInsecureSourceEndpoints", inputNames);

        HashSet<string> outputNames = ReadJsonNameSet(taskRoot.GetProperty("outputVariables"));
        Assert.Contains("exitCode", outputNames);
        Assert.Contains("findings", outputNames);
        Assert.Contains("sarifPath", outputNames);
        Assert.Contains("jsonlPath", outputNames);
        Assert.Contains("htmlPath", outputNames);
        Assert.Contains("annotations", outputNames);

        Assert.Contains("spawnSync(inputs.picketPath", handler);
        Assert.Contains("\"scan\"", handler);
        Assert.Contains("formats.includes(\"jsonl\")", handler);
        Assert.Contains("getOptionalFileInput(\"config\", target)", handler);
        Assert.Contains("getOptionalFileInput(\"baselinePath\", target)", handler);
        Assert.Contains("isDefaultInputDirectory(value, defaultDirectory)", handler);
        Assert.Contains("process.env.BUILD_SOURCESDIRECTORY", handler);
        Assert.Contains("isScannerError(exitCode, findings)", handler);
        Assert.Contains("Picket scan failed before producing findings.", handler);
        Assert.Contains("--azure-devops-token-env", handler);
        Assert.Contains("##vso[task.setvariable", handler);
        Assert.Contains("##vso[task.logissue", handler);
        Assert.Contains("##vso[artifact.upload", handler);
        Assert.Contains("require.main === module", handler);
        Assert.Contains("module.exports", handler);
        Assert.Contains("emitAnnotations", handlerTests);
        Assert.Contains("escapeProperty", handlerTests);
        Assert.Contains("node --test azure-devops/tasks/PicketScanV1/index.test.js", workflow);
        Assert.DoesNotContain("finding.secret", handler);
        Assert.DoesNotContain("finding.match", handler);
        Assert.DoesNotContain("finding.line", handler);
        Assert.Contains("Scanner execution errors always fail the task", taskMetadata);

        Assert.Contains("Picket for Azure Pipelines", readme);
        Assert.Contains("PicketScan@1", readme);
        Assert.Contains("task: PicketScan@1", readme);
        Assert.Contains("picketPath", readme);
        Assert.Contains("failOn: never", readme);
        Assert.Contains("Scanner execution errors still fail the task.", readme);
        Assert.DoesNotContain("This folder", readme);
        Assert.DoesNotContain("Before publishing", readme);
        Assert.Contains("PicketScan@1", azureDevOps);
        Assert.Contains("azure-devops/tasks/PicketScanV1/task.json", azureDevOps);
        Assert.Contains("Scanner execution errors always fail the task", azureDevOps);
        Assert.Contains("Optional `config` and `baselinePath` inputs are forwarded only when they name files", azureDevOps);
        Assert.Contains("azure-devops/vss-extension.json", marketplaces);
    }

    /// <summary>
    /// Verifies that the Azure Pipelines smoke test targets the self-hosted Windows extension environment.
    /// </summary>
    [TestMethod]
    public void AzurePipelinesSmokeTestUsesSelfHostedWindowsAgent()
    {
        string pipeline = ReadRepositoryFile("azure-pipelines.yml");
        string normalizedPipeline = pipeline.ReplaceLineEndings("\n");

        Assert.Contains("name: Windows-SelfHosted", pipeline);
        Assert.Contains("Agent.OS -equals Windows_NT", pipeline);
        Assert.Contains("PicketScan@1", pipeline);
        Assert.Contains("picket.exe", pipeline);
        Assert.Contains("trigger: none", normalizedPipeline);
        Assert.Contains("pr: none", normalizedPipeline);
        Assert.DoesNotContain("trigger:\n- main", normalizedPipeline);
        Assert.DoesNotContain("pr:\n- main", normalizedPipeline);
        Assert.Contains("pwsh:", pipeline);
        Assert.DoesNotContain("vmImage:", pipeline);
        Assert.DoesNotContain("chmod +x", pipeline);
        Assert.DoesNotContain("/picket", pipeline);
    }

    /// <summary>
    /// Verifies that hosted GitHub secret-scanning oracle capture stays opt-in and uses the dedicated secret.
    /// </summary>
    [TestMethod]
    public void LiveGitHubSecretScanningOracleWorkflowIsManualOnly()
    {
        string workflow = ReadRepositoryFile(".github/workflows/live-github-secret-scanning.yml");
        string gitHub = ReadRepositoryFile("docs/GITHUB.md");
        string marketplaces = ReadRepositoryFile("docs/MARKETPLACES.md");
        string upstream = ReadRepositoryFile("docs/UPSTREAM.md");

        Assert.Contains("workflow_dispatch:", workflow);
        Assert.DoesNotContain("pull_request:", workflow);
        Assert.DoesNotContain("push:", workflow);
        Assert.Contains("PICKET_GITHUB_SECRET_SCANNING_PAT", workflow);
        Assert.Contains("GH_TOKEN", workflow);
        Assert.Contains("Capture-GitHubSecretScanningOracle.cs", workflow);
        Assert.Contains("Compare-GitHubSecretScanningOracle.cs", workflow);
        Assert.Contains("dotnet build ./scripts/Capture-GitHubSecretScanningOracle.cs", workflow);
        Assert.Contains("dotnet run --file ./scripts/Capture-GitHubSecretScanningOracle.cs --no-build --", workflow);
        Assert.Contains("dotnet build ./scripts/Compare-GitHubSecretScanningOracle.cs", workflow);
        Assert.Contains("dotnet run --file ./scripts/Compare-GitHubSecretScanningOracle.cs --no-build --", workflow);
        Assert.Contains("--redact=100", workflow);
        Assert.Contains("actions/upload-artifact@v7", workflow);
        Assert.Contains("Secret scanning alerts", gitHub);
        Assert.Contains("Repository contents REST API", upstream);
        Assert.Contains("manual `Live GitHub Secret Scanning Oracle` workflow", marketplaces);
    }

    /// <summary>
    /// Verifies that release automation creates checksummed and attested artifacts.
    /// </summary>
    [TestMethod]
    public void ReleaseWorkflowCreatesChecksummedAttestedArtifacts()
    {
        string workflow = ReadRepositoryFile(".github/workflows/release.yml");
        string documentation = ReadRepositoryFile("docs/RELEASE.md");

        Assert.Contains("tags:", workflow);
        Assert.Contains("\"v*.*.*\"", workflow);
        Assert.Contains("workflow_dispatch", workflow);
        Assert.Contains("release-speed", workflow);
        Assert.Contains("rid: linux-x64", workflow);
        Assert.Contains("rid: linux-arm64", workflow);
        Assert.Contains("rid: win-x64", workflow);
        Assert.Contains("rid: win-arm64", workflow);
        Assert.Contains("rid: osx-x64", workflow);
        Assert.Contains("rid: osx-arm64", workflow);
        Assert.Contains("ubuntu-24.04-arm", workflow);
        Assert.Contains("windows-11-arm", workflow);
        Assert.Contains("macos-26-intel", workflow);
        Assert.Contains("actions/attest@v4", workflow);
        Assert.Contains("id-token: write", workflow);
        Assert.Contains("attestations: write", workflow);
        Assert.Contains("actions/upload-artifact@v6", workflow);
        Assert.Contains("actions/download-artifact@v5", workflow);
        Assert.Contains("build-binaries", workflow);
        Assert.Contains("release-binaries-${{ matrix.rid }}", workflow);
        Assert.Contains("release-nuget-${{ matrix.rid }}", workflow);
        Assert.Contains("dotnet publish src/Picket.Tui.Cli/Picket.Tui.Cli.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Cli/Picket.Cli.csproj --configuration Release -p:PublishProfile=release-speed -p:Version=$version -p:PackageVersion=$version -r $rid", workflow);
        Assert.Contains("dotnet pack src/Picket.Tui.Cli/Picket.Tui.Cli.csproj --configuration Release -p:PublishProfile=release-speed -p:Version=$version -p:PackageVersion=$version -r $rid", workflow);
        Assert.Contains("Smoke test GitHub Action", workflow);
        Assert.Contains("Verify GitHub Action smoke outputs", workflow);
        Assert.Contains("summary: \"false\"", workflow);
        Assert.DoesNotContain("Write GitHub Action smoke summary", workflow);
        Assert.Contains("checksums.txt", workflow);
        Assert.Contains(".sha256", workflow);
        Assert.Contains("gh release create", workflow);
        Assert.Contains("gh release upload", workflow);
        Assert.Contains("Picket.Rules/Picket.Rules.csproj", workflow);
        Assert.Contains("Picket.Engine/Picket.Engine.csproj", workflow);
        Assert.Contains("Picket.Report/Picket.Report.csproj", workflow);
        Assert.Contains("Picket.Security/Picket.Security.csproj", workflow);
        Assert.Contains("Picket.Cli/Picket.Cli.csproj", workflow);
        Assert.Contains("Picket.Tui.Cli/Picket.Tui.Cli.csproj", workflow);
        Assert.Contains("-p:IncludeSymbols=false", workflow);
        Assert.Contains("publish-nuget", workflow);
        Assert.Contains("NUGET_API_KEY", workflow);
        Assert.Contains("dotnet nuget push", workflow);
        Assert.Contains("--skip-duplicate", workflow);
        Assert.Contains("*.snupkg", workflow);
        Assert.Contains("-p:Version=$version", workflow);
        Assert.Contains("-p:PackageVersion=$version", workflow);
        Assert.Contains("pattern: release-nuget*", workflow);
        Assert.Contains("$pointerPackages", workflow);
        Assert.Contains("SHA-256 checksums", documentation);
        Assert.Contains("GitHub artifact attestations", documentation);
        Assert.Contains("publishes those `.nupkg` and `.snupkg` files to NuGet.org", documentation);
        Assert.Contains("release tag is the source of truth for package versions", documentation);
        Assert.Contains("RID-specific Native AOT NuGet tool packages", documentation);
    }

    /// <summary>
    /// Verifies that shared NuGet package metadata is defined for embeddable packages.
    /// </summary>
    [TestMethod]
    public void DirectoryBuildPropsDefinesPackageMetadata()
    {
        XElement props = ReadProjectFile("Directory.Build.props");

        AssertProjectProperty(props, "VersionPrefix", "0.1.0");
        AssertProjectProperty(props, "Authors", "willibrandon");
        AssertProjectProperty(props, "PackageLicenseExpression", "MIT");
        AssertProjectProperty(props, "PackageProjectUrl", "https://github.com/willibrandon/picket");
        AssertProjectProperty(props, "RepositoryType", "git");
        AssertProjectProperty(props, "RepositoryUrl", "https://github.com/willibrandon/picket");
        AssertProjectProperty(props, "PackageReadmeFile", "README.md");
        AssertProjectProperty(props, "PackageIcon", "icon.png");
        AssertProjectProperty(props, "Copyright", "Copyright (c) 2026 Brandon Williams");
        AssertProjectProperty(props, "PackageRequireLicenseAcceptance", "false");
        AssertProjectProperty(props, "IncludeSymbols", "true");
        AssertProjectProperty(props, "SymbolPackageFormat", "snupkg");
        AssertProjectPropertyContains(props, "PackageTags", "native-aot");
        AssertProjectPropertyContains(props, "PackageTags", "secrets");
    }

    /// <summary>
    /// Verifies that the repository carries the expected MIT license grant.
    /// </summary>
    [TestMethod]
    public void RepositoryLicenseIsMit()
    {
        string license = ReadRepositoryFile("LICENSE");

        Assert.StartsWith("MIT License", license, StringComparison.Ordinal);
        Assert.Contains("Copyright (c) 2026 Brandon Williams", license);
        Assert.Contains("Permission is hereby granted, free of charge", license);
        Assert.Contains("THE SOFTWARE IS PROVIDED \"AS IS\"", license);
    }

    /// <summary>
    /// Verifies that the public embeddable libraries have explicit NuGet package contracts.
    /// </summary>
    [TestMethod]
    public void EmbeddableProjectsDefinePackageContract()
    {
        AssertEmbeddablePackage("src/Picket.Rules/Picket.Rules.csproj", "Picket.Rules");
        AssertEmbeddablePackage("src/Picket.Engine/Picket.Engine.csproj", "Picket.Engine");
        AssertEmbeddablePackage("src/Picket.Report/Picket.Report.csproj", "Picket.Report");
        AssertEmbeddablePackage("src/Picket.Security/Picket.Security.csproj", "Picket.Security");
    }

    /// <summary>
    /// Verifies that CLI projects define the expected dotnet tool package contracts.
    /// </summary>
    [TestMethod]
    public void ToolProjectsDefinePackageContract()
    {
        AssertToolPackage("src/Picket.Cli/Picket.Cli.csproj", "Picket", "picket");
        AssertToolPackage("src/Picket.Tui.Cli/Picket.Tui.Cli.csproj", "Picket.Tui.Cli", "picket-tui");
    }

    /// <summary>
    /// Verifies that the CLI version command reports stamped assembly metadata.
    /// </summary>
    [TestMethod]
    public void CliVersionCommandUsesStampedAssemblyVersion()
    {
        string source = ReadRepositoryFile("src/Picket.Cli/Program.CommandTree.cs");

        Assert.Contains("AssemblyInformationalVersionAttribute", source);
        Assert.Contains("GetInformationalVersion()", source);
        Assert.DoesNotContain("picket dev", source);
    }

    /// <summary>
    /// Verifies that internal workflow assemblies are not accidentally packed as public APIs.
    /// </summary>
    [TestMethod]
    public void InternalProjectsAreNotAccidentallyPackable()
    {
        AssertProjectIsNotPackable("src/Picket.Analyze/Picket.Analyze.csproj");
        AssertProjectIsNotPackable("src/Picket.Compat/Picket.Compat.csproj");
        AssertProjectIsNotPackable("src/Picket.Sources/Picket.Sources.csproj");
        AssertProjectIsNotPackable("src/Picket.Store/Picket.Store.csproj");
        AssertProjectIsNotPackable("src/Picket.Verify/Picket.Verify.csproj");
    }

    /// <summary>
    /// Verifies that embedding documentation covers the public package surface.
    /// </summary>
    [TestMethod]
    public void EmbeddingDocumentationCoversPublicPackageSurface()
    {
        string documentation = ReadRepositoryFile("docs/EMBEDDING.md");

        Assert.Contains("Picket.Rules", documentation);
        Assert.Contains("Picket.Engine", documentation);
        Assert.Contains("Picket.Report", documentation);
        Assert.Contains("Picket.Security", documentation);
        Assert.Contains("net9.0", documentation);
        Assert.Contains("net10.0", documentation);
        Assert.Contains("Native AOT", documentation);
        Assert.Contains("SecretScanner.Scan", documentation);
        Assert.Contains("CompiledRuleSet.Compile", documentation);
        Assert.Contains("PicketJsonlReportWriter", documentation);
        Assert.Contains("EndpointGuard.Evaluate", documentation);
        Assert.Contains("not public library packages yet", documentation);
    }

    /// <summary>
    /// Verifies that custom live-verifier handlers document the endpoint-guard responsibility transfer.
    /// </summary>
    [TestMethod]
    public void CustomLiveVerifierHandlersDocumentEndpointGuardBoundary()
    {
        string source = ReadRepositoryFile("src/Picket.Verify/GitHubSecretLiveValidatorOptions.cs");
        int methodIndex = source.IndexOf("public void SetMessageHandlerFactory", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, methodIndex);
        int documentationStart = source.LastIndexOf("/// <summary>", methodIndex, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, documentationStart);
        string methodDocumentation = source[documentationStart..methodIndex];

        Assert.Contains("replaces the default guarded transport", methodDocumentation);
        Assert.Contains("EndpointGuardHttpHandlerFactory", methodDocumentation);
        Assert.Contains("socket connect time", methodDocumentation);
        Assert.Contains("disable automatic redirects", methodDocumentation);
        Assert.Contains("responsible for enforcing an equivalent endpoint guard boundary", methodDocumentation);
    }

    /// <summary>
    /// Verifies that remote source clients use the bounded metadata JSON reader.
    /// </summary>
    [TestMethod]
    public void RemoteSourceClientsUseBoundedMetadataJsonReader()
    {
        foreach (string file in s_remoteSourceClientFiles)
        {
            string source = ReadRepositoryFile(file);
            Assert.DoesNotContain("JsonDocument.ParseAsync", source);
            Assert.Contains("RemoteJsonDocumentReader.ReadAsync", source);
        }

        string reader = ReadRepositoryFile("src/Picket.Sources/RemoteJsonDocumentReader.cs");
        Assert.Contains("DefaultMaxMetadataBytes = 10_000_000", reader);
        Assert.Contains("CappedReadStream", reader);
    }

    /// <summary>
    /// Verifies that XML-backed remote source clients keep bounded, XXE-safe metadata readers.
    /// </summary>
    [TestMethod]
    public void RemoteXmlSourceClientsUseBoundedSafeXmlReader()
    {
        foreach (string file in s_remoteXmlSourceClientFiles)
        {
            string source = ReadRepositoryFile(file);
            Assert.Contains("CappedReadStream", source);
            Assert.Contains("DtdProcessing = DtdProcessing.Prohibit", source);
            Assert.Contains("MaxCharactersInDocument = RemoteJsonDocumentReader.DefaultMaxMetadataBytes", source);
            Assert.Contains("XmlResolver = null", source);
        }
    }

    /// <summary>
    /// Verifies that CLI source-provider wiring uses the connect-time endpoint guard.
    /// </summary>
    [TestMethod]
    public void SourceProviderWiringUsesEndpointGuardHttpHandlerFactory()
    {
        foreach (string file in s_sourceEndpointGuardWiringFiles)
        {
            string source = ReadRepositoryFile(file);
            Assert.Contains("EndpointGuardHttpHandlerFactory.Create", source);
        }
    }

    /// <summary>
    /// Verifies that required v1 documentation deliverables exist and cover their contracts.
    /// </summary>
    [TestMethod]
    public void RequiredDocumentationDeliverablesCoverCurrentContracts()
    {
        string rules = ReadRepositoryFile("docs/RULES.md");
        string parity = ReadRepositoryFile("docs/PARITY.md");
        string validation = ReadRepositoryFile("docs/VALIDATION.md");
        string reports = ReadRepositoryFile("docs/REPORTS.md");
        string cache = ReadRepositoryFile("docs/CACHE.md");
        string performance = ReadRepositoryFile("docs/PERFORMANCE.md");
        string azureDevOps = ReadRepositoryFile("docs/AZURE_DEVOPS.md");
        string marketplaces = ReadRepositoryFile("docs/MARKETPLACES.md");
        string benchmarks = ReadRepositoryFile("benchmarks/Picket.Benchmarks/SecretScanBenchmarks.cs");
        string reportWriterBenchmarks = ReadRepositoryFile("benchmarks/Picket.Benchmarks/ReportWriterBenchmarks.cs");
        string githubSecretScanningFixture = ReadRepositoryFile("tests/fixtures/github-secret-scanning/alerts.json");

        Assert.Contains("picket rules check", rules);
        Assert.Contains("picket rules test", rules);
        Assert.Contains("PICKET_CONFIG", rules);
        Assert.Contains("Strict compatibility commands ignore", rules);
        Assert.Contains("secretGroup", rules);
        Assert.Contains("targetRules", rules);
        Assert.Contains("validation", rules);
        Assert.Contains("revocation", rules);
        Assert.Contains("deprecated", rules);
        Assert.Contains("Scout `ByteRegex`", rules);
        Assert.Contains("[extend] path", rules);
        Assert.Contains("process current working directory", rules);
        Assert.Contains("trusted scanner configuration", rules);
        Assert.Contains("Local `extend.path` Resolution", parity);
        Assert.Contains("10 MiB per-file read cap", parity);
        Assert.Contains("not confined to the scan root", parity);
        Assert.Contains("Offline validation", validation);
        Assert.Contains("Live network verification is disabled by default", validation);
        Assert.Contains("picket verify --live", validation);
        Assert.Contains("picket analyze --live", validation);
        Assert.Contains("GitHub token validation", validation);
        Assert.Contains("--github-api-endpoint", validation);
        Assert.Contains("--allow-non-public-endpoints", validation);
        Assert.Contains("SSRF", validation);
        Assert.Contains("structurally-valid", validation);
        Assert.Contains("test-credential", validation);
        Assert.Contains("Picket-native validation fields", validation);
        Assert.Contains("Sourcegraph `sgp_` access token shape checks", validation);
        Assert.Contains("Gitleaks-Compatible Reports", reports);
        Assert.Contains("Picket-Native Reports", reports);
        Assert.Contains("picket.finding.v1", reports);
        Assert.Contains("picket.report.v1", reports);
        Assert.Contains("validation templates", reports);
        Assert.Contains("revocation templates", reports);
        Assert.Contains("database connection URLs", reports);
        Assert.Contains("GitLab token families", reports);
        Assert.Contains("Sourcegraph access tokens", reports);
        Assert.Contains("picket analyze", reports);
        Assert.Contains("reachable resources", reports);
        Assert.Contains("picket view", reports);
        Assert.Contains("TruffleHog JSON/JSONL", reports);
        Assert.Contains("Report readers must not print raw secrets", reports);
        Assert.Contains("strict Gitleaks-compatible commands reject `--cache-dir`", cache);
        Assert.Contains("scanner configuration fingerprint", cache);
        Assert.Contains("--cache-mode", cache);
        Assert.Contains("--ignore-gitleaks-allow", cache);
        Assert.Contains("picket.scan-cache.v3", cache);
        Assert.Contains("protected secret and match hashes", cache);
        Assert.Contains("earlier schema versions", cache);
        Assert.Contains("PicketScanCache.GetStats()", cache);
        Assert.Contains("PicketScanCache.PruneOtherKeys()", cache);
        Assert.Contains("PicketScanCache.PruneOlderThan", cache);
        Assert.Contains("PicketScanCache.Export", cache);
        Assert.Contains("PicketScanCache.Import", cache);
        Assert.Contains("picket cache stats", cache);
        Assert.Contains("picket cache prune", cache);
        Assert.Contains("picket cache export", cache);
        Assert.Contains("picket cache import", cache);
        Assert.Contains("cacheHits", cache);
        Assert.Contains("cacheMisses", cache);
        Assert.Contains("PicketScan@1", azureDevOps);
        Assert.Contains("Azure DevOps Services", azureDevOps);
        Assert.Contains("Azure DevOps Server", azureDevOps);
        Assert.Contains("Azure Repos", azureDevOps);
        Assert.Contains("--azure-devops-include-wikis", azureDevOps);
        Assert.Contains("pipeline logs", azureDevOps);
        Assert.Contains("build artifacts", azureDevOps);
        Assert.Contains("release artifacts", azureDevOps);
        Assert.Contains("job token", azureDevOps);
        Assert.Contains("PAT", azureDevOps);
        Assert.Contains("Code: Read", azureDevOps);
        Assert.Contains("Build: Read", azureDevOps);
        Assert.Contains("Release: Read", azureDevOps);
        Assert.Contains("Wiki: Read", azureDevOps);
        Assert.Contains("Packaging: Read", azureDevOps);
        Assert.Contains("no telemetry", azureDevOps);
        Assert.Contains("GitHub Marketplace", marketplaces);
        Assert.Contains("Azure DevOps Marketplace", marketplaces);
        Assert.Contains("action.yml", marketplaces);
        Assert.Contains("VSIX", marketplaces);
        Assert.Contains("PicketScan@1", marketplaces);
        Assert.Contains("checksums", marketplaces);
        Assert.Contains("attestations", marketplaces);
        Assert.Contains("Rollback", marketplaces);
        Assert.Contains("AZURE_DEVOPS_MARKETPLACE_PAT", marketplaces);
        Assert.Contains("PICKET_GITHUB_SECRET_SCANNING_PAT", marketplaces);
        Assert.DoesNotContain("`GITHUB_SECRET_SCANNING_PAT`", marketplaces);
        Assert.Contains("BenchmarkDotNet", performance);
        Assert.Contains("benchmarks/Picket.Benchmarks", performance);
        Assert.Contains("tests/fixtures/github-secret-scanning", performance);
        Assert.Contains("cacheWrites", performance);
        Assert.Contains("Capture-GitHubSecretScanningOracle.cs", performance);
        Assert.Contains("public class SecretScanBenchmarks", benchmarks);
        Assert.DoesNotContain("public sealed class SecretScanBenchmarks", benchmarks);
        Assert.Contains("ScanGitHubSecretScanningOracleFixtureWithMappedNativeRules", benchmarks);
        Assert.Contains("CompileNativeDefaultRules", benchmarks);
        Assert.Contains("CompileGitleaksCompatibilityRules", benchmarks);
        Assert.Contains("CompileGitHubSecretScanningMappedNativeRules", benchmarks);
        Assert.Contains("picket-google-api-key", benchmarks);
        Assert.Contains("public class ReportWriterBenchmarks", reportWriterBenchmarks);
        Assert.Contains("WritePicketJsonLines", reportWriterBenchmarks);
        Assert.Contains("WritePicketSarif", reportWriterBenchmarks);
        Assert.Contains("WritePicketHtml", reportWriterBenchmarks);
        Assert.Contains("WritePicketToon", reportWriterBenchmarks);
        Assert.Contains("ReportWriterBenchmarks", performance);
        Assert.Contains("report writer throughput", performance);
        Assert.Contains("picket.github-secret-scanning-oracle.v1", githubSecretScanningFixture);
        Assert.DoesNotContain("\"secret\"", githubSecretScanningFixture);
    }

    /// <summary>
    /// Verifies that the generated documentation site includes API reference pages for public packages.
    /// </summary>
    [TestMethod]
    public void GeneratedDocumentationIncludesPublicApiReference()
    {
        string siteConfig = ReadRepositoryFile("docs-site/astro.config.mjs");
        string packageJson = ReadRepositoryFile("docs-site/package.json");
        string actionReference = ReadRepositoryFile("docs-site/src/content/docs/reference/github-action.md");
        string azureDevOpsTaskReference = ReadRepositoryFile("docs-site/src/content/docs/reference/azure-devops-task.md");
        string cliReference = ReadRepositoryFile("docs-site/src/content/docs/reference/cli.md");
        string configSchema = ReadRepositoryFile("docs-site/src/content/docs/reference/config-schema.md");
        string releaseProfiles = ReadRepositoryFile("docs-site/src/content/docs/reference/release-profiles.md");
        string reportSchemas = ReadRepositoryFile("docs-site/src/content/docs/reference/report-schemas.md");
        string ruleCatalog = ReadRepositoryFile("docs-site/src/content/docs/reference/rule-catalog.md");
        string validationAnalyze = ReadRepositoryFile("docs-site/src/content/docs/reference/validation-analyze.md");
        string rulesApi = ReadRepositoryFile("docs-site/src/content/docs/api/picket-rules.md");
        string engineApi = ReadRepositoryFile("docs-site/src/content/docs/api/picket-engine.md");
        string reportApi = ReadRepositoryFile("docs-site/src/content/docs/api/picket-report.md");
        string securityApi = ReadRepositoryFile("docs-site/src/content/docs/api/picket-security.md");

        Assert.Contains("directory: \"api\"", siteConfig);
        Assert.Contains("docs:api-build", packageJson);
        Assert.Contains("Picket.Rules.csproj", packageJson);
        Assert.Contains("Picket.Engine.csproj", packageJson);
        Assert.Contains("Picket.Report.csproj", packageJson);
        Assert.Contains("Picket.Security.csproj", packageJson);
        Assert.Contains("GitHub Action Reference", actionReference);
        Assert.Contains("class=\"reference-card-list\"", actionReference);
        Assert.Contains("class=\"reference-card-description\"", actionReference);
        Assert.Contains("Azure DevOps Task Reference", azureDevOpsTaskReference);
        Assert.Contains("class=\"reference-card-list\"", azureDevOpsTaskReference);
        Assert.Contains("class=\"reference-card-description\"", azureDevOpsTaskReference);
        Assert.Contains("## Commands", cliReference);
        Assert.Contains("## Command Reference", cliReference);
        Assert.Contains("class=\"cli-command-groups\"", cliReference);
        Assert.Contains("class=\"cli-command-detail\"", cliReference);
        Assert.Contains("class=\"cli-command-detail-header\"", cliReference);
        Assert.Contains("class=\"cli-reference-table\"", cliReference);
        Assert.Contains("<code class=\"cli-command-name\">picket analyze</code>", cliReference);
        Assert.Contains("<dd>Offline or live</dd>", cliReference);
        Assert.DoesNotContain("<dd>Offline</dd>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--offline</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--live</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--verify</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--max-target-megabytes</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--timeout</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--diagnostics</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--diagnostics-dir</code></td>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--max-archive-depth</code></td>", cliReference);
        Assert.Contains("href=\"#picket-scan\"", cliReference);
        Assert.Contains("### picket git", cliReference);
        Assert.DoesNotContain("### picket cache\n", cliReference);
        Assert.DoesNotContain("### picket rules\n", cliReference);
        Assert.Contains("Config Schema Reference", configSchema);
        Assert.Contains("## Config Selection", configSchema);
        Assert.Contains("GITLEAKS_CONFIG", configSchema);
        Assert.Contains("PICKET_CONFIG", configSchema);
        Assert.Contains("[extend]", configSchema);
        Assert.Contains("[[rules]]", configSchema);
        Assert.Contains("secretGroup", configSchema);
        Assert.Contains("examples", configSchema);
        Assert.Contains("negativeExamples", configSchema);
        Assert.Contains("validation", configSchema);
        Assert.Contains("revocation", configSchema);
        Assert.Contains("deprecated", configSchema);
        Assert.Contains("[[allowlists]]", configSchema);
        Assert.Contains("targetRules", configSchema);
        Assert.Contains("regexTarget", configSchema);
        Assert.Contains("[[rules.required]]", configSchema);
        Assert.Contains("Release Profile Reference", releaseProfiles);
        Assert.Contains("release-speed", releaseProfiles);
        Assert.Contains("release-minsize", releaseProfiles);
        Assert.Contains("release-diagnostics", releaseProfiles);
        Assert.Contains("Picket.Cli", releaseProfiles);
        Assert.Contains("Picket.Tui.Cli", releaseProfiles);
        Assert.Contains("PublishAot", releaseProfiles);
        Assert.Contains("OptimizationPreference", releaseProfiles);
        Assert.Contains("PackageLicenseExpression", releaseProfiles);
        Assert.Contains("Picket.Rules", releaseProfiles);
        Assert.Contains("Picket.Engine", releaseProfiles);
        Assert.Contains("Picket.Report", releaseProfiles);
        Assert.Contains("Picket.Security", releaseProfiles);
        Assert.Contains("Scout.Text.Regex", releaseProfiles);
        Assert.Contains("System.CommandLine", releaseProfiles);
        Assert.Contains("linux-x64", releaseProfiles);
        Assert.Contains("linux-arm64", releaseProfiles);
        Assert.Contains("win-x64", releaseProfiles);
        Assert.Contains("win-arm64", releaseProfiles);
        Assert.Contains("osx-x64", releaseProfiles);
        Assert.Contains("osx-arm64", releaseProfiles);
        Assert.Contains("Report Schema Reference", reportSchemas);
        Assert.Contains("Native JSON report object", reportSchemas);
        Assert.Contains("Native JSONL finding object", reportSchemas);
        Assert.Contains("Native CSV columns", reportSchemas);
        Assert.Contains("Native TOON sections", reportSchemas);
        Assert.Contains("Native SARIF result object", reportSchemas);
        Assert.Contains("GitLab Code Quality object", reportSchemas);
        Assert.Contains("Gitleaks-compatible JSON finding object", reportSchemas);
        Assert.Contains("Gitleaks-compatible CSV columns", reportSchemas);
        Assert.Contains("Gitleaks-compatible SARIF result object", reportSchemas);
        Assert.Contains("secretSha256", reportSchemas);
        Assert.Contains("RuleID", reportSchemas);
        Assert.Contains("Rule Catalog", ruleCatalog);
        Assert.Contains("Gitleaks-compatible default", ruleCatalog);
        Assert.Contains("Picket-native additions", ruleCatalog);
        Assert.Contains("picket-aws-access-key-pair", ruleCatalog);
        Assert.Contains("picket-github-fine-grained-personal-access-token", ruleCatalog);
        Assert.Contains("offline:aws-access-key-pair", ruleCatalog);
        Assert.Contains("live:github-rest-user-v1", ruleCatalog);
        Assert.Contains("revocation:github-credentials-api", ruleCatalog);
        Assert.Contains("Gitleaks-Compatible Rules", ruleCatalog);
        Assert.Contains("aws-access-token", ruleCatalog);
        Assert.DoesNotContain("EXAMPLEEXAMPLE", ruleCatalog);
        Assert.Contains("Validation and Analyze Reference", validationAnalyze);
        Assert.Contains("## Validation States", validationAnalyze);
        Assert.Contains("`StructurallyValid`", validationAnalyze);
        Assert.Contains("`test-credential`", validationAnalyze);
        Assert.Contains("offline:aws-access-key-pair", validationAnalyze);
        Assert.Contains("live:github-rest-user-v1", validationAnalyze);
        Assert.Contains("revocation:github-credentials-api", validationAnalyze);
        Assert.Contains("class=\"reference-summary-list\"", validationAnalyze);
        Assert.Contains("class=\"reference-summary-detail\"", validationAnalyze);
        Assert.Contains("## Analyze Risk Mapping", validationAnalyze);
        Assert.Contains("| `active` | `critical` | `unknown-live`", validationAnalyze);
        Assert.Contains("| `invalid` | `low` | `unknown-offline`", validationAnalyze);
        Assert.Contains("## Provider Analysis Metadata", validationAnalyze);
        Assert.Contains("GitHub personal access token", validationAnalyze);
        Assert.Contains("GitLab personal access token", validationAnalyze);
        Assert.Contains("picket.analysis.report.v1", validationAnalyze);
        Assert.Contains("Analysis JSON `analyses[]` object", validationAnalyze);
        Assert.DoesNotContain("EXAMPLEEXAMPLE", validationAnalyze);
        Assert.DoesNotContain("ghp_", validationAnalyze);
        Assert.DoesNotContain("AKIA", validationAnalyze);
        Assert.Contains("Picket.Rules API", rulesApi);
        Assert.Contains("SecretRule", rulesApi);
        Assert.Contains("Picket.Engine API", engineApi);
        Assert.Contains("SecretScanner", engineApi);
        Assert.Contains("CompiledRuleSet", engineApi);
        Assert.Contains("Picket.Report API", reportApi);
        Assert.Contains("PicketJsonlReportWriter", reportApi);
        Assert.Contains("Picket.Security API", securityApi);
        Assert.Contains("EndpointGuard", securityApi);
    }

    /// <summary>
    /// Verifies that pull-request documentation builds do not receive Pages deployment permissions.
    /// </summary>
    [TestMethod]
    public void DocsWorkflowLimitsPagesPermissionToDeployJob()
    {
        string workflow = ReadRepositoryFile(".github/workflows/docs.yml");
        string normalizedWorkflow = workflow.ReplaceLineEndings("\n");

        Assert.AreEqual(1, PagesWritePattern().Count(normalizedWorkflow));
        Assert.Contains("deploy:\n    name: Deploy docs", normalizedWorkflow);
        Assert.Contains("permissions:\n      pages: write\n      id-token: write", normalizedWorkflow);
        Assert.DoesNotContain("build:\n    name: Build docs\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      pages: write", normalizedWorkflow);
    }

    /// <summary>
    /// Verifies that committed docs and automation do not contain machine-specific reference clone paths.
    /// </summary>
    [TestMethod]
    public void RepositoryTextDoesNotContainMachineSpecificClonePaths()
    {
        string root = FindRepositoryRoot();
        string windowsCloneRoot = string.Concat("D:", "\\", "SRC", "\\");
        string normalizedCloneRoot = string.Concat("D:", "/", "SRC", "/");
        List<string> violations = [];

        foreach (string file in EnumeratePortableTextFiles(root))
        {
            string content = File.ReadAllText(file);
            if (content.Contains(windowsCloneRoot, StringComparison.OrdinalIgnoreCase)
                || content.Contains(normalizedCloneRoot, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add(Path.GetRelativePath(root, file));
            }
        }

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that upstream oracle pins are documented through portable local clone discovery.
    /// </summary>
    [TestMethod]
    public void UpstreamDocumentationCoversPortableOracleCapture()
    {
        string documentation = ReadRepositoryFile("docs/UPSTREAM.md");
        string scriptsReadme = ReadRepositoryFile("scripts/README.md");
        string script = ReadRepositoryFile("scripts/Capture-UpstreamPins.cs");
        string oracleScript = ReadRepositoryFile("scripts/Capture-GitleaksOracle.cs");
        string compatibilityScript = ReadRepositoryFile("scripts/Capture-CompatibilityOracle.cs");
        string githubOracleScript = ReadRepositoryFile("scripts/Capture-GitHubSecretScanningOracle.cs");
        string githubComparisonScript = ReadRepositoryFile("scripts/Compare-GitHubSecretScanningOracle.cs");
        string promotionScript = ReadRepositoryFile("scripts/Promote-CompatibilityOracle.cs");
        string fixtureReadme = ReadRepositoryFile("tests/fixtures/oracles/README.md");

        Assert.Contains("PICKET_GITLEAKS_REPO", documentation);
        Assert.Contains("PICKET_SCOUT_REPO", documentation);
        Assert.Contains("PICKET_DOTNET_RUNTIME_REPO", documentation);
        Assert.Contains("scripts/Capture-UpstreamPins.cs -- -Update", documentation);
        Assert.Contains("scripts/Capture-GitleaksOracle.cs", documentation);
        Assert.Contains("scripts/Capture-CompatibilityOracle.cs", documentation);
        Assert.Contains("scripts/Capture-GitHubSecretScanningOracle.cs", documentation);
        Assert.Contains("scripts/Compare-GitHubSecretScanningOracle.cs", documentation);
        Assert.Contains("scripts/Promote-CompatibilityOracle.cs", documentation);
        Assert.Contains("dotnet build", scriptsReadme);
        Assert.Contains("dotnet run --file", scriptsReadme);
        Assert.Contains("--no-build", scriptsReadme);
        Assert.Contains("dotnet clean file-based-apps", scriptsReadme);
        Assert.Contains("#!/usr/bin/env -S dotnet --", scriptsReadme);
        Assert.Contains("Directory.Build.props", scriptsReadme);
        Assert.Contains("PICKET_GITLEAKS_BIN", documentation);
        Assert.Contains("PICKET_BIN", documentation);
        Assert.Contains("artifacts/oracles/gitleaks", documentation);
        Assert.Contains("artifacts/oracles/compatibility", documentation);
        Assert.Contains("artifacts/oracles/github-secret-scanning", documentation);
        Assert.Contains("tests/fixtures/oracles", documentation);
        Assert.Contains("RedactionMapPath", documentation);
        Assert.Contains("AllowUnredacted", documentation);
        Assert.Contains("gitleaks git <repo>", documentation);
        Assert.Contains("picket git . --profile picket", documentation);
        Assert.DoesNotContain("gitleaks git --source", documentation);
        Assert.Contains("<!-- upstream-pins:start -->", documentation);
        Assert.Contains("<!-- upstream-pins:end -->", documentation);
        Assert.Contains("PICKET_GITLEAKS_REPO", script);
        Assert.Contains("describe", script);
        Assert.Contains("rev-parse", script);
        Assert.Contains("remote", script);
        Assert.Contains("PICKET_GITLEAKS_REPO", oracleScript);
        Assert.Contains("PICKET_GITLEAKS_BIN", oracleScript);
        Assert.Contains("--report-format", oracleScript);
        Assert.Contains("--report-path", oracleScript);
        Assert.Contains("metadata.json", oracleScript);
        Assert.Contains("Capture-GitleaksOracle.cs", compatibilityScript);
        Assert.Contains("PICKET_BIN", compatibilityScript);
        Assert.Contains("comparison.json", compatibilityScript);
        Assert.Contains("FailOnDifference", compatibilityScript);
        Assert.Contains("$\"picket-{mode}.{extension}\"", compatibilityScript);
        Assert.Contains("secret-scanning/alerts", githubOracleScript);
        Assert.Contains("picket.github-secret-scanning-oracle.v1", githubOracleScript);
        Assert.Contains("ConvertToSafeAlert", githubOracleScript);
        Assert.Contains("SecretType", githubOracleScript);
        Assert.DoesNotContain("RawSecret", githubOracleScript);
        Assert.Contains("picket.github-secret-scanning-comparison.v1", githubComparisonScript);
        Assert.Contains("FailOnDifference", githubComparisonScript);
        Assert.Contains("MissingLocations", githubComparisonScript);
        Assert.Contains("CommitSha", githubComparisonScript);
        Assert.DoesNotContain("RawSecret", githubComparisonScript);
        Assert.Contains("Refusing to promote oracle captures", promotionScript);
        Assert.Contains("\"tests\", \"fixtures\", \"oracles\"", promotionScript);
        Assert.Contains("manifest.json", promotionScript);
        Assert.Contains("picket.oracle.v1", promotionScript);
        Assert.Contains("RedactionMapPath", promotionScript);
        Assert.Contains("AllowUnredacted", promotionScript);
        Assert.Contains("drive-root paths", documentation);
        Assert.Contains("scripts/Promote-CompatibilityOracle.cs", fixtureReadme);
        Assert.Contains("unredacted realistic credentials", fixtureReadme);
    }

    /// <summary>
    /// Verifies that file-based utility apps build under the same SDK path used by CI.
    /// </summary>
    [TestMethod]
    [Timeout(300000, CooperativeCancellation = true)]
    public async Task FileBasedScriptAppsBuildSuccessfully()
    {
        string root = FindRepositoryRoot();
        string[] scripts = [.. EnumerateFileBasedAppFiles(root).Order(StringComparer.Ordinal)];
        Assert.HasCount(7, scripts);

        foreach (string scriptPath in scripts)
        {
            await BuildFileBasedAppAsync(Path.GetRelativePath(root, scriptPath)).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that script app helpers have XML documentation comments on declared members.
    /// </summary>
    [TestMethod]
    public void FileBasedScriptMembersHaveXmlDocumentation()
    {
        string root = FindRepositoryRoot();
        List<string> violations = [];

        foreach (string file in EnumerateFileBasedCSharpFiles(root).Order(StringComparer.Ordinal))
        {
            string relative = Path.GetRelativePath(root, file);
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (IsDocumentableScriptMemberDeclaration(lines[i]) && !HasXmlDocumentation(lines, i))
                {
                    violations.Add($"{relative}:{i + 1}: script type and member declarations require XML documentation");
                }
            }
        }

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that the GitHub hosted-alert comparison script writes sanitized coverage gaps.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task GitHubSecretScanningComparisonScriptWritesSanitizedOutput()
    {
        using TempDirectory temp = TempDirectory.Create();
        string oraclePath = Path.Combine(temp.Path, "alerts.json");
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        string outputPath = Path.Combine(temp.Path, "comparison.json");

        File.WriteAllText(
            oraclePath,
            """
            {
              "Schema": "picket.github-secret-scanning-oracle.v1",
              "Repository": "owner/repo",
              "State": "open",
              "IncludeLocations": true,
              "CapturedUtc": "2026-07-06T00:00:00.0000000Z",
              "AlertCount": 3,
              "Summary": [
                { "SecretType": "google_api_key", "Count": 2 },
                { "SecretType": "unknown_hosted_type", "Count": 1 }
              ],
              "Alerts": [
                {
                  "Number": 1,
                  "State": "open",
                  "SecretType": "google_api_key",
                  "SecretTypeDisplayName": "Google API Key",
                  "Locations": [
                    { "Type": "commit", "Path": "src/a.cs", "StartLine": 10, "EndLine": 10, "StartColumn": 5, "EndColumn": 44, "CommitSha": "abc123" }
                  ]
                },
                {
                  "Number": 2,
                  "State": "open",
                  "SecretType": "google_api_key",
                  "SecretTypeDisplayName": "Google API Key",
                  "Locations": [
                    { "Type": "commit", "Path": "src/missing.cs", "StartLine": 20, "EndLine": 20, "StartColumn": 1, "EndColumn": 40, "CommitSha": "def456" }
                  ]
                },
                {
                  "Number": 3,
                  "State": "open",
                  "SecretType": "unknown_hosted_type",
                  "SecretTypeDisplayName": "Unknown Hosted Type",
                  "Locations": [
                    { "Type": "commit", "Path": "src/unknown.cs", "StartLine": 30, "EndLine": 30, "StartColumn": 1, "EndColumn": 40 }
                  ]
                }
              ]
            }
            """);
        File.WriteAllText(
            reportPath,
            """
            {"schema":"picket.finding.v1","ruleId":"picket-google-api-key","file":"src/a.cs","startLine":10,"startColumn":5,"commit":"abc123","fingerprint":"fp1","secret":"SHOULD_NOT_APPEAR","match":"SHOULD_NOT_APPEAR","line":"SHOULD_NOT_APPEAR"}
            {"schema":"picket.finding.v1","ruleId":"picket-google-api-key","file":"src/extra.cs","startLine":40,"startColumn":3,"commit":"abc123","fingerprint":"fp2","secret":"SHOULD_NOT_APPEAR","match":"SHOULD_NOT_APPEAR","line":"SHOULD_NOT_APPEAR"}
            """);

        await BuildFileBasedAppAsync("scripts/Compare-GitHubSecretScanningOracle.cs").ConfigureAwait(false);

        using Process process = CreateFileBasedAppProcess("scripts/Compare-GitHubSecretScanningOracle.cs", noBuild: true);
        process.StartInfo.ArgumentList.Add("-OraclePath");
        process.StartInfo.ArgumentList.Add(oraclePath);
        process.StartInfo.ArgumentList.Add("-PicketReportPath");
        process.StartInfo.ArgumentList.Add(reportPath);
        process.StartInfo.ArgumentList.Add("-OutputPath");
        process.StartInfo.ArgumentList.Add(outputPath);

        Assert.IsTrue(process.Start(), "Could not start pwsh.");
        (string stdout, string stderr) = await WaitForExitAndReadOutputAsync(process, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, process.ExitCode, string.Concat(stdout, stderr));
        string comparison = File.ReadAllText(outputPath);
        Assert.DoesNotContain("SHOULD_NOT_APPEAR", comparison);

        using JsonDocument document = JsonDocument.Parse(comparison);
        JsonElement root = document.RootElement;
        Assert.AreEqual("picket.github-secret-scanning-comparison.v1", root.GetProperty("Schema").GetString());
        Assert.AreEqual(1, root.GetProperty("MissingLocationCount").GetInt32());
        Assert.AreEqual(1, root.GetProperty("UnexpectedLocationCount").GetInt32());
        Assert.AreEqual(1, root.GetProperty("UnmappedAlertTypeCount").GetInt32());
        Assert.AreEqual("def456", root.GetProperty("MissingLocations")[0].GetProperty("CommitSha").GetString());
        Assert.AreEqual("abc123", root.GetProperty("UnexpectedLocations")[0].GetProperty("Commit").GetString());
    }

    /// <summary>
    /// Verifies that the GitHub hosted-alert capture script can write alerts without location data.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task GitHubSecretScanningCaptureScriptAllowsAlertsWithoutLocations()
    {
        using TempDirectory temp = TempDirectory.Create();
        string toolsPath = Path.Combine(temp.Path, "tools");
        Directory.CreateDirectory(toolsPath);
        WriteFakeGitHubCli(toolsPath);
        string outputPath = Path.Combine(temp.Path, "alerts.json");

        await BuildFileBasedAppAsync("scripts/Capture-GitHubSecretScanningOracle.cs").ConfigureAwait(false);

        using Process process = CreateFileBasedAppProcess("scripts/Capture-GitHubSecretScanningOracle.cs", noBuild: true);
        process.StartInfo.Environment["PATH"] = string.Concat(
            toolsPath,
            Path.PathSeparator,
            Environment.GetEnvironmentVariable("PATH"));
        process.StartInfo.ArgumentList.Add("-Repository");
        process.StartInfo.ArgumentList.Add("owner/repo");
        process.StartInfo.ArgumentList.Add("-State");
        process.StartInfo.ArgumentList.Add("all");
        process.StartInfo.ArgumentList.Add("-OutputPath");
        process.StartInfo.ArgumentList.Add(outputPath);

        Assert.IsTrue(process.Start(), "Could not start pwsh.");
        (string stdout, string stderr) = await WaitForExitAndReadOutputAsync(process, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, process.ExitCode, string.Concat(stdout, stderr));
        string capture = File.ReadAllText(outputPath);
        Assert.DoesNotContain("SHOULD_NOT_APPEAR", capture);

        using JsonDocument document = JsonDocument.Parse(capture);
        JsonElement root = document.RootElement;
        Assert.AreEqual("picket.github-secret-scanning-oracle.v1", root.GetProperty("Schema").GetString());
        Assert.IsFalse(root.GetProperty("IncludeLocations").GetBoolean());
        Assert.AreEqual(1, root.GetProperty("AlertCount").GetInt32());
        Assert.AreEqual("google_api_key", root.GetProperty("Summary")[0].GetProperty("SecretType").GetString());
        Assert.AreEqual(0, root.GetProperty("Alerts")[0].GetProperty("Locations").GetArrayLength());
    }

    /// <summary>
    /// Verifies that checked-in PowerShell scripts parse successfully.
    /// </summary>
    [TestMethod]
    [Timeout(300000, CooperativeCancellation = true)]
    public async Task PowerShellScriptsParseSuccessfully()
    {
        string root = FindRepositoryRoot();
        string[] scripts = [.. Directory.EnumerateFiles(root, "*.ps1", SearchOption.AllDirectories)
            .Where(file => IsPortableTextFile(root, file))
            .Order(StringComparer.Ordinal)];
        if (scripts.Length == 0)
        {
            return;
        }

        using Process process = new()
        {
            StartInfo = new ProcessStartInfo("pwsh")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };

        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-Command");
        process.StartInfo.ArgumentList.Add("""
            $failed = $false
            foreach ($path in $args)
            {
                $tokens = $null
                $errors = $null
                [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) > $null
                foreach ($errorRecord in $errors)
                {
                    [Console]::Error.WriteLine("${path}: $($errorRecord.Message)")
                    $failed = $true
                }
            }

            if ($failed)
            {
                exit 1
            }
            """);

        foreach (string script in scripts)
        {
            process.StartInfo.ArgumentList.Add(script);
        }

        Assert.IsTrue(process.Start(), "Could not start pwsh.");
        (string stdout, string stderr) = await WaitForExitAndReadOutputAsync(process, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, process.ExitCode, string.Concat(stdout, stderr));
    }

    private static async Task<(string StandardOutput, string StandardError)> WaitForExitAndReadOutputAsync(Process process, CancellationToken cancellationToken)
    {
        using CancellationTokenRegistration cancellationRegistration = cancellationToken.Register(static state =>
        {
            var startedProcess = (Process)state!;
            try
            {
                if (!startedProcess.HasExited)
                {
                    startedProcess.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }
        }, process);
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        string stdout = await stdoutTask.ConfigureAwait(false);
        string stderr = await stderrTask.ConfigureAwait(false);

        return (stdout, stderr);
    }

    private async Task BuildFileBasedAppAsync(string relativePath)
    {
        await s_fileBasedAppBuildLock.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using Process process = CreateDotNetProcess();
            process.StartInfo.ArgumentList.Add("build");
            process.StartInfo.ArgumentList.Add(ResolveRepositoryPath(relativePath));
            process.StartInfo.ArgumentList.Add("--nologo");
            process.StartInfo.ArgumentList.Add("--verbosity");
            process.StartInfo.ArgumentList.Add("quiet");

            Assert.IsTrue(process.Start(), "Could not start dotnet.");
            (string stdout, string stderr) = await WaitForExitAndReadOutputAsync(process, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(0, process.ExitCode, string.Concat(relativePath, Environment.NewLine, stdout, stderr));
        }
        finally
        {
            s_fileBasedAppBuildLock.Release();
        }
    }

    private static Process CreateFileBasedAppProcess(string relativePath, bool noBuild)
    {
        Process process = CreateDotNetProcess();
        process.StartInfo.ArgumentList.Add("run");
        process.StartInfo.ArgumentList.Add("--file");
        process.StartInfo.ArgumentList.Add(ResolveRepositoryPath(relativePath));
        if (noBuild)
        {
            process.StartInfo.ArgumentList.Add("--no-build");
        }

        process.StartInfo.ArgumentList.Add("--");
        return process;
    }

    private static Process CreateDotNetProcess()
    {
        return new Process
        {
            StartInfo = new ProcessStartInfo("dotnet")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };
    }

    private static void WriteFakeGitHubCli(string toolsPath)
    {
        const string AlertsJson = """
            [[{"number":1,"state":"open","secret_type":"google_api_key","secret_type_display_name":"Google API Key","created_at":"2026-07-06T00:00:00Z","updated_at":"2026-07-06T00:00:00Z","resolved_at":null,"resolution":null,"html_url":"https://example.invalid/alerts/1","locations_url":"https://example.invalid/locations","secret":"SHOULD_NOT_APPEAR"}]]
            """;
        if (OperatingSystem.IsWindows())
        {
            string scriptPath = Path.Combine(toolsPath, "gh.cmd");
            File.WriteAllText(
                scriptPath,
                string.Concat(
                    "@echo off\n",
                    "echo ",
                    AlertsJson.Trim(),
                    "\n",
                    "exit /b 0\n"));
            return;
        }

        string executablePath = Path.Combine(toolsPath, "gh");
        File.WriteAllText(
            executablePath,
            string.Concat(
                "#!/bin/sh\n",
                "cat <<'JSON'\n",
                AlertsJson.Trim(),
                "\nJSON\n"));
        File.SetUnixFileMode(
            executablePath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static bool IsFileBasedApp(string path)
    {
        string? firstLine = File.ReadLines(path).FirstOrDefault();
        return string.Equals(firstLine, "#!/usr/bin/env -S dotnet --", StringComparison.Ordinal);
    }

    private static IEnumerable<string> EnumerateFileBasedAppFiles(string root)
    {
        foreach (string file in EnumerateFileBasedCSharpFiles(root))
        {
            if (IsFileBasedApp(file))
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> EnumerateFileBasedCSharpFiles(string root)
    {
        foreach (string directory in s_fileBasedAppDirectories)
        {
            string path = Path.Combine(root, directory);
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (string file in Directory.EnumerateFiles(path, "*.cs", SearchOption.TopDirectoryOnly))
            {
                yield return file;
            }
        }
    }

    private static bool IsDocumentableScriptMemberDeclaration(string line)
    {
        string trimmed = line.TrimStart();
        if (!trimmed.StartsWith("internal ", StringComparison.Ordinal)
            && !trimmed.StartsWith("private ", StringComparison.Ordinal)
            && !trimmed.StartsWith("public ", StringComparison.Ordinal)
            && !trimmed.StartsWith("protected ", StringComparison.Ordinal))
        {
            return false;
        }

        return trimmed.Contains(" class ", StringComparison.Ordinal)
            || trimmed.Contains(" struct ", StringComparison.Ordinal)
            || trimmed.Contains(" interface ", StringComparison.Ordinal)
            || trimmed.Contains(" enum ", StringComparison.Ordinal)
            || trimmed.Contains(" delegate ", StringComparison.Ordinal)
            || trimmed.Contains(" static ", StringComparison.Ordinal)
            || trimmed.StartsWith("private const ", StringComparison.Ordinal)
            || trimmed.StartsWith("internal const ", StringComparison.Ordinal)
            || trimmed.StartsWith("public const ", StringComparison.Ordinal);
    }

    private static bool HasXmlDocumentation(string[] lines, int declarationLineIndex)
    {
        for (int i = declarationLineIndex - 1; i >= 0; i--)
        {
            string trimmed = lines[i].TrimStart();
            if (trimmed.Length == 0)
            {
                continue;
            }

            return trimmed.StartsWith("///", StringComparison.Ordinal);
        }

        return false;
    }

    [GeneratedRegex(
        @"^\s*(?:(?:public|internal|private|protected|file)\s+)*(?:(?:abstract|sealed|static|partial|readonly|ref|unsafe)\s+)*(?:record\s+)?(?:class|struct|interface|enum|delegate)\s+",
        RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex CreateTypeDeclarationPattern();

    [GeneratedRegex("pages: write", RegexOptions.CultureInvariant)]
    private static partial Regex PagesWritePattern();

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Picket.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find repository root.");
    }

    private static bool IsRepositorySourceFile(string root, string file)
    {
        string relative = Path.GetRelativePath(root, file);
        string normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
        return !normalized.Equals("src/Picket.Cli/Program.cs", StringComparison.Ordinal)
            && !relative.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            && !relative.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private static bool IsRepositoryCSharpFile(string root, string file)
    {
        string relative = Path.GetRelativePath(root, file);
        string normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
        return (normalized.StartsWith("src/", StringComparison.Ordinal)
                || normalized.StartsWith("tests/", StringComparison.Ordinal)
                || normalized.StartsWith("tools/", StringComparison.Ordinal)
                || normalized.StartsWith("scripts/", StringComparison.Ordinal)
                || normalized.StartsWith(".github/actions/", StringComparison.Ordinal)
                || normalized.StartsWith("benchmarks/", StringComparison.Ordinal))
            && !relative.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            && !relative.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private static string GetUsingSortKey(string usingDirective)
    {
        string key = usingDirective["using ".Length..].Trim();
        return key.EndsWith(';') ? key[..^1] : key;
    }

    private static IEnumerable<string> EnumeratePortableTextFiles(string root)
    {
        foreach (string relativePath in s_portableTextRoots)
        {
            string path = ResolveRepositoryPath(relativePath);
            if (File.Exists(path))
            {
                yield return path;
                continue;
            }

            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (string file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                if (IsPortableTextFile(root, file))
                {
                    yield return file;
                }
            }
        }
    }

    private static bool IsPortableTextFile(string root, string file)
    {
        string relative = Path.GetRelativePath(root, file);
        string normalized = relative.Replace(Path.DirectorySeparatorChar, '/');
        if (normalized.Contains("/bin/", StringComparison.Ordinal)
            || normalized.Contains("/obj/", StringComparison.Ordinal)
            || normalized.Contains("/node_modules/", StringComparison.Ordinal)
            || normalized.StartsWith("TestResults/", StringComparison.Ordinal)
            || normalized.StartsWith("artifacts/", StringComparison.Ordinal))
        {
            return false;
        }

        return Path.GetExtension(file) switch
        {
            ".cs" or ".js" or ".json" or ".md" or ".ps1" or ".txt" or ".yaml" or ".yml" => true,
            _ => false,
        };
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        return File.ReadAllText(ResolveRepositoryPath(relativePath));
    }

    private static XElement ReadProjectFile(string relativePath)
    {
        return XElement.Load(ResolveRepositoryPath(relativePath));
    }

    private static HashSet<string> ReadJsonNameSet(JsonElement array)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement item in array.EnumerateArray())
        {
            if (item.TryGetProperty("name", out JsonElement name))
            {
                names.Add(name.GetString() ?? string.Empty);
            }
        }

        return names;
    }

    private static XElement ReadPublishProfile(string name)
    {
        string path = Path.Combine(
            FindRepositoryRoot(),
            "src",
            "Picket.Cli",
            "Properties",
            "PublishProfiles",
            string.Concat(name, ".pubxml"));
        Assert.IsTrue(File.Exists(path), $"Missing publish profile: {name}");
        return XElement.Load(path);
    }

    private static XElement ReadPublishProfile(string projectRelativePath, string name)
    {
        string path = Path.Combine(
            FindRepositoryRoot(),
            projectRelativePath.Replace('/', Path.DirectorySeparatorChar),
            "Properties",
            "PublishProfiles",
            string.Concat(name, ".pubxml"));
        Assert.IsTrue(File.Exists(path), $"Missing publish profile: {projectRelativePath}/{name}");
        return XElement.Load(path);
    }

    private static void AssertCommonNativeAotProfile(XElement profile)
    {
        AssertProfileProperty(profile, "Configuration", "Release");
        AssertProfileProperty(profile, "PublishAot", "true");
        AssertProfileProperty(profile, "SelfContained", "true");
        AssertProfileProperty(profile, "PublishSingleFile", "true");
        AssertProfileProperty(profile, "InvariantGlobalization", "true");
        AssertProfileProperty(profile, "EnableUnsafeBinaryFormatterSerialization", "false");
        AssertProfileProperty(profile, "EnableUnsafeUTF7Encoding", "false");
        AssertProfileProperty(profile, "MetadataUpdaterSupport", "false");
        AssertProfileProperty(profile, "XmlResolverIsNetworkingEnabledByDefault", "false");
        AssertProfileProperty(profile, "Http3Support", "false");
    }

    private static void AssertProfileProperty(XElement profile, string name, string expected)
    {
        AssertProjectProperty(profile, name, expected);
    }

    private static void AssertProfileProperty(XElement profile, string name, string condition, string expected)
    {
        XElement[] properties = profile.Element("PropertyGroup")?
            .Elements(name)
            .Where(element => string.Equals((string?)element.Attribute("Condition"), condition, StringComparison.Ordinal))
            .ToArray() ?? [];
        Assert.HasCount(1, properties, $"Unexpected project property {name} with condition {condition}.");
        Assert.AreEqual(expected, properties[0].Value, $"Unexpected project property {name} with condition {condition}.");
    }

    private static void AssertProfileStripSymbolsExceptMacOs(XElement profile)
    {
        AssertProfileProperty(profile, "StripSymbols", MacOsStripSymbolsCondition, "false");
        AssertProfileProperty(profile, "StripSymbols", NonMacOsStripSymbolsCondition, "true");
    }

    private static void AssertProfileDisablesMacOsNativeDebugSymbols(XElement profile)
    {
        AssertProfileProperty(profile, "DebugSymbols", MacOsStripSymbolsCondition, "false");
        AssertProfileProperty(profile, "DebugType", MacOsStripSymbolsCondition, "none");
        AssertProfileProperty(profile, "NativeDebugSymbols", MacOsStripSymbolsCondition, "false");
    }

    private static void AssertEmbeddablePackage(string relativePath, string packageId)
    {
        XElement project = ReadProjectFile(relativePath);

        AssertProjectProperty(project, "TargetFrameworks", "net9.0;net10.0");
        AssertProjectProperty(project, "IsPackable", "true");
        AssertProjectProperty(project, "PackageId", packageId);
        AssertProjectPropertyIsNotEmpty(project, "Description");
        AssertProjectPropertyContains(project, "PackageTags", "$(PackageTags)");
        AssertProjectProperty(project, "IsAotCompatible", "true");
        AssertProjectProperty(project, "EnableTrimAnalyzer", "true");
        AssertProjectProperty(project, "EnableAotAnalyzer", "true");
        AssertProjectProperty(project, "EnableSingleFileAnalyzer", "true");
    }

    private static void AssertToolPackage(string relativePath, string packageId, string commandName)
    {
        XElement project = ReadProjectFile(relativePath);

        AssertProjectProperty(project, "TargetFramework", "net10.0");
        AssertProjectProperty(project, "IsPackable", "true");
        AssertProjectProperty(project, "PackAsTool", "true");
        AssertProjectProperty(project, "ToolCommandName", commandName);
        AssertProjectProperty(project, "PackageId", packageId);
        AssertProjectProperty(project, "PublishAot", "true");
        AssertProjectProperty(project, "ToolPackageRuntimeIdentifiers", "win-x64;win-arm64;linux-x64;linux-arm64;osx-x64;osx-arm64");
        AssertProjectPropertyIsNotEmpty(project, "Description");
        AssertProjectPropertyContains(project, "PackageTags", "$(PackageTags)");
        AssertProjectProperty(project, "IsAotCompatible", "true");
        AssertProjectProperty(project, "EnableTrimAnalyzer", "true");
        AssertProjectProperty(project, "EnableAotAnalyzer", "true");
        AssertProjectProperty(project, "EnableSingleFileAnalyzer", "true");
    }

    private static void AssertProjectIsNotPackable(string relativePath)
    {
        AssertProjectProperty(ReadProjectFile(relativePath), "IsPackable", "false");
    }

    private static void AssertProjectProperty(XElement project, string name, string expected)
    {
        string? actual = ReadProjectProperty(project, name);
        Assert.AreEqual(expected, actual, $"Unexpected project property {name}.");
    }

    private static void AssertProjectPropertyContains(XElement project, string name, string expected)
    {
        string actual = ReadRequiredProjectProperty(project, name);
        Assert.Contains(expected, actual);
    }

    private static void AssertProjectPropertyIsNotEmpty(XElement project, string name)
    {
        string actual = ReadRequiredProjectProperty(project, name);
        Assert.AreNotEqual(string.Empty, actual, $"Project property {name} must not be empty.");
    }

    private static string? ReadProjectProperty(XElement project, string name)
    {
        return project.Element("PropertyGroup")?.Element(name)?.Value;
    }

    private static void AssertProjectItem(
        XElement project,
        string itemName,
        string include,
        string metadataName,
        string metadataValue)
    {
        foreach (XElement item in project.Elements("ItemGroup").Elements(itemName))
        {
            if (item.Attribute("Include")?.Value == include
                && item.Attribute(metadataName)?.Value == metadataValue)
            {
                return;
            }
        }

        Assert.Fail($"Missing project item {itemName} Include={include} {metadataName}={metadataValue}.");
    }

    private static string ReadRequiredProjectProperty(XElement project, string name)
    {
        string? actual = ReadProjectProperty(project, name);
        if (actual is null)
        {
            Assert.Fail($"Missing project property {name}.");
        }

        return actual;
    }

    private static string ResolveRepositoryPath(string relativePath)
    {
        return Path.Combine(FindRepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
    }
}
