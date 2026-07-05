using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="DirectorySource" />.
/// </summary>
[TestClass]
public sealed class DirectorySourceTests
{
    /// <summary>
    /// Verifies that compatibility enumeration does not apply Scout's default ignore behavior.
    /// </summary>
    [TestMethod]
    public void EnumerateIncludesGitIgnoredAndHiddenFilesForCompatibility()
    {
        string root = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(root, ".gitignore"), "ignored.txt");
            File.WriteAllText(Path.Combine(root, "ignored.txt"), "secret");
            File.WriteAllText(Path.Combine(root, ".hidden"), "hidden");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains(".hidden", displayPaths);
            Assert.Contains(".gitignore", displayPaths);
            Assert.Contains("ignored.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that the max-target byte cap filters large files before scanning.
    /// </summary>
    [TestMethod]
    public void EnumerateAppliesMaxTargetBytes()
    {
        string root = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(root, "small.txt"), "123");
            File.WriteAllText(Path.Combine(root, "large.txt"), "123456");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxTargetBytes: 3));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains("small.txt", displayPaths);
            Assert.DoesNotContain("large.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
