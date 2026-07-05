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
}
