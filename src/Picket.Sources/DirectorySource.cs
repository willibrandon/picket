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

            string scanFullPath = entry.FullPath;
            string displayPath = CreateDisplayPath(options.Root, entry.FullPath);
            string symlinkDisplayPath = string.Empty;
            if (IsPathOrAncestorAllowed(options.IsPathAllowed, displayPath))
            {
                continue;
            }

            if (entry.IsSymbolicLink)
            {
                if (!TryResolveSymlinkFile(entry.FullPath, out scanFullPath))
                {
                    continue;
                }

                symlinkDisplayPath = displayPath;
                displayPath = CreateDisplayPath(options.Root, scanFullPath);
            }

            AddSourceFile(sourceFiles, options, scanFullPath, displayPath, symlinkDisplayPath);
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
        string displayPath = Path.GetFileName(options.Root);
        if (!IsPathAllowed(options.IsPathAllowed, displayPath))
        {
            string scanFullPath = options.Root;
            string symlinkDisplayPath = string.Empty;
            if (IsSymbolicLink(options.Root))
            {
                if (!options.FollowSymbolicLinks || !TryResolveSymlinkFile(options.Root, out scanFullPath))
                {
                    return sourceFiles;
                }

                symlinkDisplayPath = displayPath;
                displayPath = Path.GetFileName(scanFullPath);
            }

            AddSourceFile(sourceFiles, options, scanFullPath, displayPath, symlinkDisplayPath);
        }

        return sourceFiles;
    }

    private static void AddSourceFile(
        List<SourceFile> sourceFiles,
        DirectoryScanOptions options,
        string fullPath,
        string displayPath,
        string symlinkDisplayPath)
    {
        if (ArchiveReader.IsArchiveFile(fullPath))
        {
            if (options.MaxArchiveDepth > 0)
            {
                var entries = new List<ArchiveEntry>();
                if (ArchiveReader.TryReadFileEntries(
                    fullPath,
                    displayPath,
                    options.MaxArchiveDepth,
                    options.MaxTargetBytes,
                    options.IsPathAllowed,
                    entries))
                {
                    foreach (ArchiveEntry entry in entries)
                    {
                        sourceFiles.Add(new SourceFile(fullPath, entry.DisplayPath, symlinkDisplayPath, entry.Content));
                    }
                }
            }

            return;
        }

        sourceFiles.Add(new SourceFile(fullPath, displayPath, symlinkDisplayPath));
    }

    private static FileWalkerOptions CreateWalkerOptions(DirectoryScanOptions options)
    {
        var walkerOptions = new FileWalkerOptions
        {
            IgnoreHidden = options.IgnoreHidden,
            FollowSymbolicLinks = options.FollowSymbolicLinks,
            ReadParentIgnoreFiles = options.ReadParentIgnoreFiles,
            ReadIgnoreFiles = options.ReadIgnoreFiles,
            ReadGitIgnoreFiles = options.ReadGitIgnoreFiles,
            ReadGitExcludeFiles = options.ReadGitIgnoreFiles,
            ReadGlobalGitIgnore = options.ReadGlobalGitIgnore,
            RequireGitRepository = options.ReadGitIgnoreFiles,
            Sort = FileWalkSort.FullPath,
            MaxFileSize = options.MaxTargetBytes,
        };

        if (options.ReadPicketIgnoreFiles)
        {
            walkerOptions.CustomIgnoreFileNames.Add(".picketignore");
        }

        for (int i = 0; i < options.IgnoreFilePaths.Count; i++)
        {
            walkerOptions.IgnoreFiles.Add(options.IgnoreFilePaths[i]);
        }

        return walkerOptions;
    }

    private static string CreateDisplayPath(string root, string fullPath)
    {
        string relativePath = Path.GetRelativePath(root, fullPath);
        return relativePath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }

    private static bool IsSymbolicLink(string path)
    {
        return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    }

    private static bool TryResolveSymlinkFile(string path, out string fullPath)
    {
        try
        {
            FileSystemInfo? target = new FileInfo(path).ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null && File.Exists(target.FullName))
            {
                fullPath = target.FullName;
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        fullPath = string.Empty;
        return false;
    }

    private static bool IsPathOrAncestorAllowed(Func<string, bool>? isPathAllowed, string displayPath)
    {
        if (IsPathAllowed(isPathAllowed, displayPath))
        {
            return true;
        }

        int separatorIndex = displayPath.Length;
        while ((separatorIndex = displayPath.LastIndexOf('/', separatorIndex - 1)) > 0)
        {
            if (IsPathAllowed(isPathAllowed, displayPath[..separatorIndex]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPathAllowed(Func<string, bool>? isPathAllowed, string displayPath)
    {
        return isPathAllowed is not null && isPathAllowed(displayPath);
    }
}
