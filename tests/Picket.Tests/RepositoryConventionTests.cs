using System.Text.RegularExpressions;

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
}
