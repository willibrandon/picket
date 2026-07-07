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
        Assert.Contains("run-picket.ps1", action);
    }

    /// <summary>
    /// Verifies that the GitHub Action helper emits stable outputs without requiring raw secret logs.
    /// </summary>
    [TestMethod]
    public void GitHubActionHelperDefinesStableOutputs()
    {
        string helper = ReadRepositoryFile(".github/actions/run-picket.ps1");

        Assert.Contains("GITHUB_OUTPUT", helper);
        Assert.Contains("GITHUB_STEP_SUMMARY", helper);
        Assert.Contains("picket.sarif", helper);
        Assert.Contains("picket.jsonl", helper);
        Assert.Contains("--redact=$redact", helper);
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
        Assert.Contains("ConvertFrom-Json", helper);
        Assert.Contains("::warning", helper);
        Assert.Contains("PICKET_ANNOTATIONS", helper);
        Assert.Contains("PICKET_ANNOTATION_LIMIT", helper);
        Assert.Contains("Get-FindingBreakdownSummaryLines", helper);
        Assert.Contains("Findings by rule", helper);
        Assert.Contains("Findings by file", helper);
        Assert.Contains("ConvertTo-MarkdownCell", helper);
        Assert.DoesNotContain("finding.secret", helper);
        Assert.DoesNotContain("finding.match", helper);
        Assert.DoesNotContain("finding.line", helper);
        Assert.Contains("'should-fail'", helper);
        Assert.Contains("'failure-code'", helper);
        Assert.Contains("'annotations'", helper);
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
        Assert.Contains("CI Smoke", documentation);
        Assert.Contains("sanitized GitHub secret-scanning fixture", documentation);
    }

    /// <summary>
    /// Verifies that named Native AOT publish profiles match the release design contract.
    /// </summary>
    [TestMethod]
    public void CliPublishProfilesMatchReleaseContract()
    {
        XElement cliProject = ReadProjectFile("src/Picket.Cli/Picket.Cli.csproj");
        XElement speed = ReadPublishProfile("release-speed");
        XElement minSize = ReadPublishProfile("release-minsize");
        XElement diagnostics = ReadPublishProfile("release-diagnostics");

        AssertProjectProperty(cliProject, "VerifyReferenceTrimCompatibility", "true");
        AssertProjectProperty(cliProject, "VerifyReferenceAotCompatibility", "true");
        AssertProjectProperty(cliProject, "TrimmerSingleWarn", "false");
        AssertCommonNativeAotProfile(speed);
        AssertCommonNativeAotProfile(minSize);
        AssertCommonNativeAotProfile(diagnostics);
        AssertProfileProperty(speed, "OptimizationPreference", "Speed");
        AssertProfileProperty(speed, "StripSymbols", "true");
        AssertProfileProperty(speed, "DebuggerSupport", "false");
        AssertProfileProperty(minSize, "OptimizationPreference", "Size");
        AssertProfileProperty(minSize, "StripSymbols", "true");
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

        Assert.Contains("Pack public packages", workflow);
        Assert.Contains("Publish Native AOT CLI", workflow);
        Assert.Contains("dotnet publish src/Picket.Cli/Picket.Cli.csproj", workflow);
        Assert.Contains("PublishProfile=release-speed", workflow);
        Assert.Contains("${{ matrix.rid }}", workflow);
        Assert.Contains("rid: linux-x64", workflow);
        Assert.Contains("rid: win-x64", workflow);
        Assert.Contains("rid: osx-arm64", workflow);
        Assert.Contains("Smoke test GitHub Action", workflow);
        Assert.Contains("uses: ./", workflow);
        Assert.Contains("path: tests/fixtures/github-secret-scanning", workflow);
        Assert.Contains("setup-dotnet: \"false\"", workflow);
        Assert.Contains("summary: \"false\"", workflow);
        Assert.Contains("Verify GitHub Action smoke outputs", workflow);
        Assert.DoesNotContain("Write GitHub Action smoke summary", workflow);
        Assert.Contains("dotnet pack src/Picket.Rules/Picket.Rules.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Engine/Picket.Engine.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Report/Picket.Report.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Security/Picket.Security.csproj", workflow);
        Assert.Contains("--no-build", workflow);
        Assert.Contains("shell: pwsh", workflow);
        Assert.Contains("ubuntu-latest", workflow);
        Assert.Contains("windows-latest", workflow);
        Assert.Contains("macos-26", workflow);
        Assert.Contains("NuGet Package Validation", documentation);
        Assert.Contains("Every CI run packs the public embeddable packages", documentation);
        Assert.Contains("cross-platform MSBuild paths", documentation);
        Assert.Contains("Native AOT Publish Validation", documentation);
        Assert.Contains("Every CI run also publishes the CLI with `release-speed`", documentation);
        Assert.Contains("normal `dotnet build` is not enough evidence", documentation);
        Assert.Contains("GitHub Action Smoke Validation", documentation);
        Assert.Contains("both `picket.sarif` and `picket.jsonl`", documentation);
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
        Assert.Contains("rid: win-x64", workflow);
        Assert.Contains("rid: osx-arm64", workflow);
        Assert.Contains("actions/attest@v4", workflow);
        Assert.Contains("id-token: write", workflow);
        Assert.Contains("attestations: write", workflow);
        Assert.Contains("actions/upload-artifact@v6", workflow);
        Assert.Contains("actions/download-artifact@v5", workflow);
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
        Assert.Contains("SHA-256 checksums", documentation);
        Assert.Contains("GitHub artifact attestations", documentation);
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
    /// Verifies that internal workflow assemblies are not accidentally packed as public APIs.
    /// </summary>
    [TestMethod]
    public void InternalProjectsAreNotAccidentallyPackable()
    {
        AssertProjectIsNotPackable("src/Picket.Analyze/Picket.Analyze.csproj");
        AssertProjectIsNotPackable("src/Picket.Cli/Picket.Cli.csproj");
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
        Assert.Contains("not public packages yet", documentation);
    }

    /// <summary>
    /// Verifies that required v1 documentation deliverables exist and cover their contracts.
    /// </summary>
    [TestMethod]
    public void RequiredDocumentationDeliverablesCoverCurrentContracts()
    {
        string rules = ReadRepositoryFile("docs/RULES.md");
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
        Assert.Contains("Older entries for the legacy raw/path mode without creation, address-mode, storage-mode, and finding-count metadata remain readable", cache);
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
        Assert.Contains("Capture-GitHubSecretScanningOracle.ps1", performance);
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
        string cliReference = ReadRepositoryFile("docs-site/src/content/docs/reference/cli.md");
        string configSchema = ReadRepositoryFile("docs-site/src/content/docs/reference/config-schema.md");
        string reportSchemas = ReadRepositoryFile("docs-site/src/content/docs/reference/report-schemas.md");
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
        Assert.Contains("## Commands", cliReference);
        Assert.Contains("## Command Reference", cliReference);
        Assert.Contains("class=\"cli-command-groups\"", cliReference);
        Assert.Contains("class=\"cli-command-detail\"", cliReference);
        Assert.Contains("class=\"cli-command-detail-header\"", cliReference);
        Assert.Contains("class=\"cli-reference-table\"", cliReference);
        Assert.Contains("<code class=\"cli-command-name\">picket analyze</code>", cliReference);
        Assert.Contains("<dd>Offline or live</dd>", cliReference);
        Assert.DoesNotContain("<dd>Offline</dd>", cliReference);
        Assert.Contains("<td data-label=\"Option\"><code>--offline / --live</code></td>", cliReference);
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
        Assert.Contains("[[allowlists]]", configSchema);
        Assert.Contains("targetRules", configSchema);
        Assert.Contains("regexTarget", configSchema);
        Assert.Contains("[[rules.required]]", configSchema);
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
        string script = ReadRepositoryFile("scripts/Capture-UpstreamPins.ps1");
        string oracleScript = ReadRepositoryFile("scripts/Capture-GitleaksOracle.ps1");
        string compatibilityScript = ReadRepositoryFile("scripts/Capture-CompatibilityOracle.ps1");
        string githubOracleScript = ReadRepositoryFile("scripts/Capture-GitHubSecretScanningOracle.ps1");
        string githubComparisonScript = ReadRepositoryFile("scripts/Compare-GitHubSecretScanningOracle.ps1");
        string promotionScript = ReadRepositoryFile("scripts/Promote-CompatibilityOracle.ps1");
        string fixtureReadme = ReadRepositoryFile("tests/fixtures/oracles/README.md");

        Assert.Contains("PICKET_GITLEAKS_REPO", documentation);
        Assert.Contains("PICKET_SCOUT_REPO", documentation);
        Assert.Contains("PICKET_DOTNET_RUNTIME_REPO", documentation);
        Assert.Contains("scripts/Capture-UpstreamPins.ps1 -Update", documentation);
        Assert.Contains("scripts/Capture-GitleaksOracle.ps1", documentation);
        Assert.Contains("scripts/Capture-CompatibilityOracle.ps1", documentation);
        Assert.Contains("scripts/Capture-GitHubSecretScanningOracle.ps1", documentation);
        Assert.Contains("scripts/Compare-GitHubSecretScanningOracle.ps1", documentation);
        Assert.Contains("scripts/Promote-CompatibilityOracle.ps1", documentation);
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
        Assert.Contains("Capture-GitleaksOracle.ps1", compatibilityScript);
        Assert.Contains("PICKET_BIN", compatibilityScript);
        Assert.Contains("comparison.json", compatibilityScript);
        Assert.Contains("FailOnDifference", compatibilityScript);
        Assert.Contains("picket-$Mode", compatibilityScript);
        Assert.Contains("secret-scanning/alerts", githubOracleScript);
        Assert.Contains("picket.github-secret-scanning-oracle.v1", githubOracleScript);
        Assert.Contains("ConvertTo-SafeAlert", githubOracleScript);
        Assert.Contains("SecretType", githubOracleScript);
        Assert.DoesNotContain("RawSecret", githubOracleScript);
        Assert.Contains("picket.github-secret-scanning-comparison.v1", githubComparisonScript);
        Assert.Contains("FailOnDifference", githubComparisonScript);
        Assert.Contains("MissingLocations", githubComparisonScript);
        Assert.Contains("CommitSha", githubComparisonScript);
        Assert.DoesNotContain("RawSecret", githubComparisonScript);
        Assert.Contains("Refusing to promote oracle captures", promotionScript);
        Assert.Contains("tests\\fixtures\\oracles", promotionScript);
        Assert.Contains("manifest.json", promotionScript);
        Assert.Contains("picket.oracle.v1", promotionScript);
        Assert.Contains("RedactionMapPath", promotionScript);
        Assert.Contains("AllowUnredacted", promotionScript);
        Assert.Contains("drive-root paths", documentation);
        Assert.Contains("scripts/Promote-CompatibilityOracle.ps1", fixtureReadme);
        Assert.Contains("unredacted realistic credentials", fixtureReadme);
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
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(ResolveRepositoryPath("scripts/Compare-GitHubSecretScanningOracle.ps1"));
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

        using Process process = new()
        {
            StartInfo = new ProcessStartInfo("pwsh")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };

        process.StartInfo.Environment["PATH"] = string.Concat(
            toolsPath,
            Path.PathSeparator,
            Environment.GetEnvironmentVariable("PATH"));
        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(ResolveRepositoryPath("scripts/Capture-GitHubSecretScanningOracle.ps1"));
        process.StartInfo.ArgumentList.Add("-Repository");
        process.StartInfo.ArgumentList.Add("owner/repo");
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
        Assert.IsNotEmpty(scripts);

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

    private static void WriteFakeGitHubCli(string toolsPath)
    {
        const string AlertsJson = """
            [[{"number":1,"state":"open","secret_type":"google_api_key","secret_type_display_name":"Google API Key","created_at":"2026-07-06T00:00:00Z","updated_at":"2026-07-06T00:00:00Z","resolved_at":null,"resolution":null,"html_url":"https://example.invalid/alerts/1","locations_url":"https://example.invalid/locations","secret":"SHOULD_NOT_APPEAR"}]]
            """;
        if (OperatingSystem.IsWindows())
        {
            string scriptPath = Path.Combine(toolsPath, "gh.ps1");
            File.WriteAllText(
                scriptPath,
                string.Concat(
                    "param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)\n",
                    "Write-Output @'\n",
                    AlertsJson.Trim(),
                    "\n'@\n",
                    "exit 0\n"));
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

    [GeneratedRegex(
        @"^\s*(?:(?:public|internal|private|protected|file)\s+)*(?:(?:abstract|sealed|static|partial|readonly|ref|unsafe)\s+)*(?:record\s+)?(?:class|struct|interface|enum|delegate)\s+",
        RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex CreateTypeDeclarationPattern();

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

    private static IEnumerable<string> EnumeratePortableTextFiles(string root)
    {
        foreach (string relativePath in new[] { "AGENTS.md", "docs", "docs-site/src/content/docs", "scripts", ".github", "src", "tests" })
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
            || normalized.StartsWith("TestResults/", StringComparison.Ordinal)
            || normalized.StartsWith("artifacts/", StringComparison.Ordinal))
        {
            return false;
        }

        return Path.GetExtension(file) switch
        {
            ".cs" or ".json" or ".md" or ".ps1" or ".txt" or ".yaml" or ".yml" => true,
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

    private static void AssertEmbeddablePackage(string relativePath, string packageId)
    {
        XElement project = ReadProjectFile(relativePath);

        AssertProjectProperty(project, "TargetFrameworks", "net9.0;net10.0");
        AssertProjectProperty(project, "IsPackable", "true");
        AssertProjectProperty(project, "PackageId", packageId);
        AssertProjectPropertyIsNotEmpty(project, "Description");
        AssertProjectProperty(project, "PackageReadmeFile", "README.md");
        AssertProjectPropertyContains(project, "PackageTags", "$(PackageTags)");
        AssertProjectProperty(project, "IsAotCompatible", "true");
        AssertProjectProperty(project, "EnableTrimAnalyzer", "true");
        AssertProjectProperty(project, "EnableAotAnalyzer", "true");
        AssertProjectProperty(project, "EnableSingleFileAnalyzer", "true");
        AssertProjectItem(
            project,
            "None",
            @"..\..\docs\EMBEDDING.md",
            "Pack",
            "true");
        AssertProjectItem(
            project,
            "None",
            @"..\..\docs\EMBEDDING.md",
            "PackagePath",
            "README.md");
        AssertProjectItem(
            project,
            "None",
            @"..\..\docs\EMBEDDING.md",
            "Link",
            "README.md");
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
