using System.IO.Compression;
using System.Text;
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

    /// <summary>
    /// Verifies that followed symlink files keep both resolved target and symlink report paths.
    /// </summary>
    [TestMethod]
    public void EnumerateReportsSymlinkFileWhenFollowingSymlinks()
    {
        string root = CreateTempDirectory();
        try
        {
            string targetPath = Path.Combine(root, "target.txt");
            string linkPath = Path.Combine(root, "link.txt");
            File.WriteAllText(targetPath, "token-12345");
            File.CreateSymbolicLink(linkPath, targetPath);

            IReadOnlyList<SourceFile> defaultFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root));
            IReadOnlyList<SourceFile> followedFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root, followSymbolicLinks: true));
            SourceFile? symlinkFile = followedFiles.FirstOrDefault(file => file.SymlinkDisplayPath == "link.txt");

            Assert.IsFalse(defaultFiles.Any(file => file.SymlinkDisplayPath == "link.txt"));
            Assert.IsNotNull(symlinkFile);
            Assert.AreEqual("target.txt", symlinkFile.DisplayPath);
            Assert.AreEqual(Path.GetFullPath(targetPath), symlinkFile.FullPath);
            Assert.AreEqual("token-12345", Encoding.UTF8.GetString(symlinkFile.ReadAllBytes()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that archive containers are skipped when archive traversal is disabled.
    /// </summary>
    [TestMethod]
    public void EnumerateSkipsZipArchivesByDefault()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteZipFile(Path.Combine(root, "secrets.zip"), ("secret.txt", "token-12345"));

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.DoesNotContain("secrets.zip", displayPaths);
            Assert.DoesNotContain("secrets.zip!secret.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that zip archive entries are yielded as virtual source files when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public void EnumerateExpandsZipArchivesWhenDepthEnabled()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteZipFile(Path.Combine(root, "secrets.zip"), ("nested/secret.txt", "token-12345"));

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 1));
            SourceFile? file = files.FirstOrDefault(file => file.DisplayPath == "secrets.zip!nested/secret.txt");

            Assert.IsNotNull(file);
            Assert.AreEqual("token-12345", Encoding.UTF8.GetString(file.ReadAllBytes()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that tar archive entries are yielded as virtual source files when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public void EnumerateExpandsTarArchivesWhenDepthEnabled()
    {
        string root = CreateTempDirectory();
        try
        {
            File.WriteAllBytes(Path.Combine(root, "secrets.tar"), TarTestData.CreateTarBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("token-12345"))));

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 1));
            SourceFile? file = files.FirstOrDefault(file => file.DisplayPath == "secrets.tar!nested/secret.txt");

            Assert.IsNotNull(file);
            Assert.AreEqual("token-12345", Encoding.UTF8.GetString(file.ReadAllBytes()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that gzip-compressed tar archive entries are yielded with archive provenance.
    /// </summary>
    [TestMethod]
    public void EnumerateExpandsGzipTarArchivesWhenDepthEnabled()
    {
        string root = CreateTempDirectory();
        try
        {
            byte[] tarBytes = TarTestData.CreateTarBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("token-12345")));
            File.WriteAllBytes(Path.Combine(root, "secrets.tar.gz"), TarTestData.CreateGzipBytes(tarBytes));

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 1));
            SourceFile? file = files.FirstOrDefault(file => file.DisplayPath == "secrets.tar.gz!nested/secret.txt");

            Assert.IsNotNull(file);
            Assert.AreEqual("token-12345", Encoding.UTF8.GetString(file.ReadAllBytes()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that unsafe archive entry paths are skipped before they reach reports or scanners.
    /// </summary>
    [TestMethod]
    public void EnumerateSkipsUnsafeArchiveEntryPaths()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteZipFile(
                Path.Combine(root, "secrets.zip"),
                ("../parent.txt", "parent-token"),
                ("/absolute.txt", "absolute-token"),
                ("C:/drive.txt", "drive-token"),
                ("safe/secret.txt", "token-12345"));

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 1));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains("secrets.zip!safe/secret.txt", displayPaths);
            Assert.DoesNotContain("secrets.zip!../parent.txt", displayPaths);
            Assert.DoesNotContain("secrets.zip!absolute.txt", displayPaths);
            Assert.DoesNotContain("secrets.zip!C:/drive.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that nested zip archive traversal honors the configured archive depth.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsZipArchiveDepth()
    {
        string root = CreateTempDirectory();
        try
        {
            byte[] innerArchive = CreateZipBytes(("secret.txt", Encoding.UTF8.GetBytes("token-12345")));
            File.WriteAllBytes(Path.Combine(root, "outer.zip"), CreateZipBytes(("inner.zip", innerArchive)));

            IReadOnlyList<SourceFile> shallowFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 1));
            IReadOnlyList<SourceFile> recursiveFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 2));
            string[] shallowDisplayPaths = [.. shallowFiles.Select(file => file.DisplayPath)];
            string[] recursiveDisplayPaths = [.. recursiveFiles.Select(file => file.DisplayPath)];

            Assert.DoesNotContain("outer.zip!inner.zip!secret.txt", shallowDisplayPaths);
            Assert.Contains("outer.zip!inner.zip!secret.txt", recursiveDisplayPaths);
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

    private static void WriteZipFile(string path, params (string Name, string Content)[] entries)
    {
        File.WriteAllBytes(path, CreateZipBytes([.. entries.Select(entry => (entry.Name, Encoding.UTF8.GetBytes(entry.Content)))]));
    }

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }

}
