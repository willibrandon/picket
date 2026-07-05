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
        XElement speed = ReadPublishProfile("release-speed");
        XElement minSize = ReadPublishProfile("release-minsize");
        XElement diagnostics = ReadPublishProfile("release-diagnostics");

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
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), relativePath));
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
        string? actual = profile.Element("PropertyGroup")?.Element(name)?.Value;
        Assert.AreEqual(expected, actual, $"Unexpected publish profile property {name}.");
    }
}
