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
        Assert.Contains("annotations", action);
        Assert.Contains("annotation-limit", action);
        Assert.Contains("cache-path", action);
        Assert.Contains("redact", action);
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
        Assert.Contains("--max-target-megabytes", helper);
        Assert.Contains("ConvertFrom-Json", helper);
        Assert.Contains("::warning", helper);
        Assert.Contains("PICKET_ANNOTATIONS", helper);
        Assert.Contains("PICKET_ANNOTATION_LIMIT", helper);
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
        Assert.Contains("annotation-limit", documentation);
        Assert.Contains("Annotations", documentation);
        Assert.Contains("redact: 0", documentation);
        Assert.Contains("upload-sarif", documentation);
        Assert.Contains("cache-path", documentation);
        Assert.Contains("actions/cache/restore", documentation);
        Assert.Contains("actions/cache/save", documentation);
        Assert.Contains("picket.sarif", documentation);
        Assert.Contains("picket.jsonl", documentation);
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
        Assert.Contains("dotnet pack src/Picket.Rules/Picket.Rules.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Engine/Picket.Engine.csproj", workflow);
        Assert.Contains("dotnet pack src/Picket.Report/Picket.Report.csproj", workflow);
        Assert.Contains("--no-build", workflow);
        Assert.Contains("shell: pwsh", workflow);
        Assert.Contains("ubuntu-latest", workflow);
        Assert.Contains("windows-latest", workflow);
        Assert.Contains("macos-26", workflow);
        Assert.Contains("NuGet Package Validation", documentation);
        Assert.Contains("Every CI run packs the public embeddable packages", documentation);
        Assert.Contains("cross-platform MSBuild paths", documentation);
    }

    /// <summary>
    /// Verifies that shared NuGet package metadata is defined for embeddable packages.
    /// </summary>
    [TestMethod]
    public void DirectoryBuildPropsDefinesPackageMetadata()
    {
        XElement props = ReadProjectFile("Directory.Build.props");

        AssertProjectProperty(props, "VersionPrefix", "0.1.0");
        AssertProjectProperty(props, "Authors", "Picket contributors");
        AssertProjectProperty(props, "PackageLicenseExpression", "MIT");
        AssertProjectProperty(props, "PackageProjectUrl", "https://github.com/willibrandon/picket");
        AssertProjectProperty(props, "RepositoryType", "git");
        AssertProjectProperty(props, "RepositoryUrl", "https://github.com/willibrandon/picket");
        AssertProjectProperty(props, "PackageRequireLicenseAcceptance", "false");
        AssertProjectProperty(props, "IncludeSymbols", "true");
        AssertProjectProperty(props, "SymbolPackageFormat", "snupkg");
        AssertProjectPropertyContains(props, "PackageTags", "native-aot");
        AssertProjectPropertyContains(props, "PackageTags", "secrets");
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
        Assert.Contains("net9.0", documentation);
        Assert.Contains("net10.0", documentation);
        Assert.Contains("Native AOT", documentation);
        Assert.Contains("SecretScanner.Scan", documentation);
        Assert.Contains("CompiledRuleSet.Compile", documentation);
        Assert.Contains("PicketJsonlReportWriter", documentation);
        Assert.Contains("not public packages yet", documentation);
        Assert.Contains("Scout is consumed through NuGet", documentation);
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

        Assert.Contains("picket rules check", rules);
        Assert.Contains("picket rules test", rules);
        Assert.Contains("secretGroup", rules);
        Assert.Contains("targetRules", rules);
        Assert.Contains("Scout `ByteRegex`", rules);
        Assert.Contains("NuGet package references", rules);
        Assert.Contains("Offline validation", validation);
        Assert.Contains("Live network verification is disabled by default", validation);
        Assert.Contains("SSRF", validation);
        Assert.Contains("structurally-valid", validation);
        Assert.Contains("test-credential", validation);
        Assert.Contains("Picket-native validation fields", validation);
        Assert.Contains("Gitleaks-Compatible Reports", reports);
        Assert.Contains("Picket-Native Reports", reports);
        Assert.Contains("picket.finding.v1", reports);
        Assert.Contains("picket.report.v1", reports);
        Assert.Contains("picket view", reports);
        Assert.Contains("TruffleHog JSON/JSONL", reports);
        Assert.Contains("Report readers must not print raw secrets", reports);
        Assert.Contains("strict Gitleaks-compatible commands reject `--cache-dir`", cache);
        Assert.Contains("scanner configuration fingerprint", cache);
        Assert.Contains("Older entries without creation and finding-count metadata remain readable", cache);
        Assert.Contains("PicketScanCache.GetStats()", cache);
        Assert.Contains("PicketScanCache.PruneOtherKeys()", cache);
        Assert.Contains("PicketScanCache.PruneOlderThan", cache);
        Assert.Contains("picket cache stats", cache);
        Assert.Contains("picket cache prune", cache);
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
