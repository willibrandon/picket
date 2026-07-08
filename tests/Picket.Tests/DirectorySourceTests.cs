using Picket.Sources;
using System.IO.Compression;
using System.Text;

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
            File.WriteAllText(Path.Combine(root, ".picketignore"), "picket-ignored.txt");
            File.WriteAllText(Path.Combine(root, ".gitignore"), "ignored.txt");
            File.WriteAllText(Path.Combine(root, "ignored.txt"), "secret");
            File.WriteAllText(Path.Combine(root, "picket-ignored.txt"), "secret");
            File.WriteAllText(Path.Combine(root, ".hidden"), "hidden");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains(".hidden", displayPaths);
            Assert.Contains(".gitignore", displayPaths);
            Assert.Contains(".picketignore", displayPaths);
            Assert.Contains("ignored.txt", displayPaths);
            Assert.Contains("picket-ignored.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that native enumeration can apply per-directory .picketignore rules.
    /// </summary>
    [TestMethod]
    public void EnumerateCanApplyPicketIgnoreFiles()
    {
        string root = CreateTempDirectory();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "secrets"));
            Directory.CreateDirectory(Path.Combine(root, "keep"));
            File.WriteAllText(Path.Combine(root, ".picketignore"), "secrets/\n*.tmp\n");
            File.WriteAllText(Path.Combine(root, "secrets", "token.txt"), "token-12345");
            File.WriteAllText(Path.Combine(root, "keep", "scratch.tmp"), "token-23456");
            File.WriteAllText(Path.Combine(root, "keep", "token.txt"), "token-34567");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, readPicketIgnoreFiles: true));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains(".picketignore", displayPaths);
            Assert.Contains("keep/token.txt", displayPaths);
            Assert.DoesNotContain("secrets/token.txt", displayPaths);
            Assert.DoesNotContain("keep/scratch.tmp", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that native enumeration can apply Scout standard ignore, Git ignore, and hidden-file policy.
    /// </summary>
    [TestMethod]
    public void EnumerateCanApplyNativeScoutIgnorePolicy()
    {
        string root = CreateTempDirectory();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, ".git"));
            File.WriteAllText(Path.Combine(root, ".gitignore"), "git-ignored.txt\n");
            File.WriteAllText(Path.Combine(root, ".ignore"), "dot-ignored.txt\n");
            File.WriteAllText(Path.Combine(root, ".hidden.txt"), "token-12345");
            File.WriteAllText(Path.Combine(root, "git-ignored.txt"), "token-23456");
            File.WriteAllText(Path.Combine(root, "dot-ignored.txt"), "token-34567");
            File.WriteAllText(Path.Combine(root, "keep.txt"), "token-45678");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                readIgnoreFiles: true,
                readGitIgnoreFiles: true,
                readGlobalGitIgnore: true,
                ignoreHidden: true,
                readParentIgnoreFiles: true));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains("keep.txt", displayPaths);
            Assert.DoesNotContain(".gitignore", displayPaths);
            Assert.DoesNotContain(".ignore", displayPaths);
            Assert.DoesNotContain(".hidden.txt", displayPaths);
            Assert.DoesNotContain("git-ignored.txt", displayPaths);
            Assert.DoesNotContain("dot-ignored.txt", displayPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that native enumeration can apply explicit ignore files through Scout.
    /// </summary>
    [TestMethod]
    public void EnumerateCanApplyExplicitIgnoreFile()
    {
        string root = CreateTempDirectory();
        try
        {
            string ignorePath = Path.Combine(root, "picket.ignore");
            File.WriteAllText(ignorePath, "ignored.txt\n");
            File.WriteAllText(Path.Combine(root, "ignored.txt"), "token-12345");
            File.WriteAllText(Path.Combine(root, "keep.txt"), "token-23456");

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, ignoreFilePaths: [ignorePath]));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.Contains("keep.txt", displayPaths);
            Assert.DoesNotContain("ignored.txt", displayPaths);
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

            Assert.DoesNotContain("link.txt", defaultFiles.Select(file => file.SymlinkDisplayPath));
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
    /// Verifies followed directory symlinks do not escape the scan root.
    /// </summary>
    [TestMethod]
    public void EnumerateDoesNotFollowSymlinkFilesOutsideRoot()
    {
        string root = CreateTempDirectory();
        string outsideRoot = CreateTempDirectory();
        try
        {
            string outsidePath = Path.Combine(outsideRoot, "outside.txt");
            string linkPath = Path.Combine(root, "outside-link.txt");
            File.WriteAllText(outsidePath, "token-12345");
            File.CreateSymbolicLink(linkPath, outsidePath);

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, followSymbolicLinks: true));

            Assert.DoesNotContain("outside-link.txt", files.Select(file => file.SymlinkDisplayPath));
            Assert.DoesNotContain("../", string.Join('\n', files.Select(file => file.DisplayPath)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            Directory.Delete(outsideRoot, recursive: true);
        }
    }

    /// <summary>
    /// Verifies followed directory symlinks keep both resolved target and symlink report paths.
    /// </summary>
    [TestMethod]
    public void EnumerateReportsDirectorySymlinkFileWhenFollowingSymlinks()
    {
        string root = CreateTempDirectory();
        try
        {
            string targetDirectory = Path.Combine(root, "target");
            string targetPath = Path.Combine(targetDirectory, "secret.txt");
            string linkPath = Path.Combine(root, "link");
            Directory.CreateDirectory(targetDirectory);
            File.WriteAllText(targetPath, "token-12345");
            Directory.CreateSymbolicLink(linkPath, targetDirectory);

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, followSymbolicLinks: true));
            SourceFile? symlinkFile = files.FirstOrDefault(file => file.SymlinkDisplayPath == "link/secret.txt");

            Assert.IsNotNull(symlinkFile);
            Assert.AreEqual("target/secret.txt", symlinkFile.DisplayPath);
            Assert.AreEqual(Path.GetFullPath(targetPath), symlinkFile.FullPath);
            Assert.AreEqual("token-12345", Encoding.UTF8.GetString(symlinkFile.ReadAllBytes()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies followed directory symlinks do not escape the scan root.
    /// </summary>
    [TestMethod]
    public void EnumerateDoesNotFollowDirectorySymlinksOutsideRoot()
    {
        string root = CreateTempDirectory();
        string outsideRoot = CreateTempDirectory();
        try
        {
            string outsidePath = Path.Combine(outsideRoot, "secret.txt");
            string linkPath = Path.Combine(root, "outside");
            File.WriteAllText(outsidePath, "token-12345");
            Directory.CreateSymbolicLink(linkPath, outsideRoot);

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, followSymbolicLinks: true));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];
            string[] symlinkDisplayPaths = [.. files.Select(file => file.SymlinkDisplayPath)];
            string[] fullPaths = [.. files.Select(file => file.FullPath)];

            Assert.DoesNotContain("outside/secret.txt", displayPaths);
            Assert.DoesNotContain("outside/secret.txt", symlinkDisplayPaths);
            Assert.DoesNotContain(Path.GetFullPath(outsidePath), fullPaths);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            Directory.Delete(outsideRoot, recursive: true);
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
    /// Verifies that gzip nesting consumes archive depth instead of bypassing the configured limit.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsNestedGzipArchiveDepth()
    {
        string root = CreateTempDirectory();
        try
        {
            byte[] content = TarTestData.CreateTarBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("token-12345")));
            for (int i = 0; i < 8; i++)
            {
                content = TarTestData.CreateGzipBytes(content);
            }

            File.WriteAllBytes(Path.Combine(root, "secrets.gz"), content);

            IReadOnlyList<SourceFile> shallowFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 2));
            IReadOnlyList<SourceFile> recursiveFiles = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxArchiveDepth: 9));
            string[] shallowDisplayPaths = [.. shallowFiles.Select(file => file.DisplayPath)];
            string[] recursiveDisplayPaths = [.. recursiveFiles.Select(file => file.DisplayPath)];

            Assert.DoesNotContain("secrets.gz!nested/secret.txt", shallowDisplayPaths);
            Assert.Contains("secrets.gz!nested/secret.txt", recursiveDisplayPaths);
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

    /// <summary>
    /// Verifies that archive enumeration honors the configured entry-count safety cap.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsArchiveEntryLimit()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteZipFile(
                Path.Combine(root, "secrets.zip"),
                ("first.txt", "token-12345"),
                ("second.txt", "token-23456"));
            var warnings = new List<string>();

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                maxArchiveDepth: 1,
                maxArchiveEntries: 1,
                warningSink: warnings.Add));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.HasCount(1, files);
            Assert.Contains("secrets.zip!first.txt", displayPaths);
            Assert.DoesNotContain("secrets.zip!second.txt", displayPaths);
            Assert.HasCount(1, warnings);
            Assert.Contains("archive entry limit reached after 1 entries while reading secrets.zip", warnings[0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that archive enumeration honors the configured decompressed byte safety cap.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsArchiveByteLimit()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteZipFile(
                Path.Combine(root, "secrets.zip"),
                ("first.txt", "token-12345"),
                ("second.txt", "token-23456"));
            var warnings = new List<string>();

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                maxArchiveDepth: 1,
                maxArchiveBytes: 11,
                warningSink: warnings.Add));
            string[] displayPaths = [.. files.Select(file => file.DisplayPath)];

            Assert.HasCount(1, files);
            Assert.Contains("secrets.zip!first.txt", displayPaths);
            Assert.DoesNotContain("secrets.zip!second.txt", displayPaths);
            Assert.HasCount(1, warnings);
            Assert.Contains("archive byte limit reached while reading secrets.zip", warnings[0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that zip size metadata is not trusted for archive byte accounting.
    /// </summary>
    [TestMethod]
    public void EnumerateChargesZipEntriesByActualBytesRead()
    {
        string root = CreateTempDirectory();
        try
        {
            byte[] archive = CreateZipBytes(("secret.txt", Encoding.UTF8.GetBytes(new string('x', 1024))));
            OverwriteZipUncompressedSizes(archive, 1_000_000);
            File.WriteAllBytes(Path.Combine(root, "secrets.zip"), archive);
            var warnings = new List<string>();

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                maxArchiveDepth: 1,
                maxArchiveBytes: 2_048,
                warningSink: warnings.Add));
            SourceFile? file = files.FirstOrDefault(file => file.DisplayPath == "secrets.zip!secret.txt");

            Assert.IsNotNull(file);
            Assert.HasCount(1024, file.ReadAllBytes());
            Assert.IsEmpty(warnings);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that archive enumeration rejects entries whose declared size understates the real decompressed size.
    /// </summary>
    [TestMethod]
    public void EnumerateRejectsZipEntryWithUnderstatedUncompressedSize()
    {
        string root = CreateTempDirectory();
        try
        {
            byte[] archive = CreateZipBytes(("secret.txt", Encoding.UTF8.GetBytes(new string('x', 1024))));
            OverwriteZipUncompressedSizes(archive, 1);
            File.WriteAllBytes(Path.Combine(root, "secrets.zip"), archive);
            var warnings = new List<string>();

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                maxArchiveDepth: 1,
                maxArchiveBytes: 2_048,
                warningSink: warnings.Add));

            Assert.IsEmpty(files);
            Assert.HasCount(1, warnings);
            Assert.Contains("archive size metadata mismatch while reading secrets.zip", warnings[0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that archive enumeration honors the configured compression-ratio safety cap.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsArchiveCompressionRatioLimit()
    {
        string root = CreateTempDirectory();
        try
        {
            WriteCompressedZipFile(
                Path.Combine(root, "secrets.zip"),
                ("secret.txt", string.Concat("token-12345\n", new string('!', 8192))));
            var warnings = new List<string>();

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                root,
                maxArchiveDepth: 1,
                warningSink: warnings.Add,
                maxArchiveCompressionRatio: 1));

            Assert.IsEmpty(files);
            Assert.HasCount(1, warnings);
            Assert.Contains("archive compression ratio limit reached while reading secrets.zip", warnings[0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that archive enumeration stops when cancellation is requested.
    /// </summary>
    [TestMethod]
    public void EnumerateStopsArchiveReadWhenCancellationIsRequested()
    {
        string root = CreateTempDirectory();
        try
        {
            string archivePath = Path.Combine(root, "secrets.zip");
            WriteZipFile(archivePath, ("secret.txt", "token-12345"));
            var warnings = new List<string>();
            int checks = 0;

            IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
                archivePath,
                maxArchiveDepth: 1,
                warningSink: warnings.Add,
                isCancellationRequested: () => ++checks > 3));

            Assert.IsEmpty(files);
            Assert.HasCount(1, warnings);
            Assert.Contains("archive read stopped because cancellation was requested while reading secrets.zip", warnings[0]);
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

    private static void WriteCompressedZipFile(string path, params (string Name, string Content)[] entries)
    {
        File.WriteAllBytes(path, CreateZipBytes(CompressionLevel.SmallestSize, [.. entries.Select(entry => (entry.Name, Encoding.UTF8.GetBytes(entry.Content)))]));
    }

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        return CreateZipBytes(CompressionLevel.NoCompression, entries);
    }

    private static byte[] CreateZipBytes(CompressionLevel compressionLevel, params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, compressionLevel);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }

    private static void OverwriteZipUncompressedSizes(byte[] archive, int uncompressedSize)
    {
        for (int i = 0; i <= archive.Length - 4; i++)
        {
            if (archive[i] == 0x50
                && archive[i + 1] == 0x4b
                && archive[i + 2] == 0x03
                && archive[i + 3] == 0x04)
            {
                WriteUInt32LittleEndian(archive.AsSpan(i + 22, 4), uncompressedSize);
            }
            else if (archive[i] == 0x50
                && archive[i + 1] == 0x4b
                && archive[i + 2] == 0x01
                && archive[i + 3] == 0x02)
            {
                WriteUInt32LittleEndian(archive.AsSpan(i + 24, 4), uncompressedSize);
            }
        }
    }

    private static void WriteUInt32LittleEndian(Span<byte> destination, int value)
    {
        destination[0] = (byte)value;
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)(value >> 16);
        destination[3] = (byte)(value >> 24);
    }
}
