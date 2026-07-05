using Scout.IO.Ignore;

namespace Picket.Sources;

/// <summary>
/// Enumerates filesystem sources for compatibility-mode scans.
/// </summary>
public sealed class DirectorySource
{
    /// <summary>
    /// Enumerates regular files selected by the supplied options.
    /// </summary>
    /// <param name="options">The directory scan options.</param>
    /// <returns>The source files in deterministic order.</returns>
    public static IReadOnlyList<SourceFile> Enumerate(DirectoryScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (File.Exists(options.Root))
        {
            return EnumerateSingleFile(options);
        }

        if (!Directory.Exists(options.Root))
        {
            throw new DirectoryNotFoundException(options.Root);
        }

        var sourceFiles = new List<SourceFile>();
        var walker = new FileWalker(CreateWalkerOptions(options));
        foreach (FileWalkEntry entry in walker.Enumerate(options.Root))
        {
            if (!entry.IsFile)
            {
                continue;
            }

            AddSourceFile(sourceFiles, options, entry.FullPath, CreateDisplayPath(options.Root, entry.FullPath));
        }

        return sourceFiles;
    }

    private static IReadOnlyList<SourceFile> EnumerateSingleFile(DirectoryScanOptions options)
    {
        FileInfo fileInfo = new(options.Root);
        if (options.MaxTargetBytes.HasValue && fileInfo.Length > options.MaxTargetBytes.Value)
        {
            return [];
        }

        var sourceFiles = new List<SourceFile>();
        AddSourceFile(sourceFiles, options, options.Root, Path.GetFileName(options.Root));
        return sourceFiles;
    }

    private static void AddSourceFile(List<SourceFile> sourceFiles, DirectoryScanOptions options, string fullPath, string displayPath)
    {
        if (ZipArchiveReader.IsZipFile(fullPath))
        {
            if (options.MaxArchiveDepth > 0)
            {
                var entries = new List<ArchiveEntry>();
                if (ZipArchiveReader.TryReadFileEntries(fullPath, displayPath, options.MaxArchiveDepth, options.MaxTargetBytes, entries))
                {
                    foreach (ArchiveEntry entry in entries)
                    {
                        sourceFiles.Add(new SourceFile(fullPath, entry.DisplayPath, entry.Content));
                    }
                }
            }

            return;
        }

        sourceFiles.Add(new SourceFile(fullPath, displayPath));
    }

    private static FileWalkerOptions CreateWalkerOptions(DirectoryScanOptions options)
    {
        return new FileWalkerOptions
        {
            IgnoreHidden = false,
            FollowSymbolicLinks = options.FollowSymbolicLinks,
            ReadParentIgnoreFiles = false,
            ReadIgnoreFiles = false,
            ReadGitIgnoreFiles = false,
            ReadGitExcludeFiles = false,
            ReadGlobalGitIgnore = false,
            RequireGitRepository = false,
            Sort = FileWalkSort.FullPath,
            MaxFileSize = options.MaxTargetBytes,
        };
    }

    private static string CreateDisplayPath(string root, string fullPath)
    {
        string relativePath = Path.GetRelativePath(root, fullPath);
        return relativePath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }
}
