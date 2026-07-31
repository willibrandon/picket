using Scout.IO.Globbing;
using Scout.IO.Ignore;

namespace Picket.Sources;

/// <summary>
/// Enumerates filesystem sources for compatibility-mode scans.
/// </summary>
public sealed class DirectorySource
{
    private static readonly char[] s_pathSeparators = [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    /// <summary>
    /// Enumerates regular files selected by the supplied options.
    /// </summary>
    /// <param name="options">The directory scan options.</param>
    /// <returns>The source files in deterministic order.</returns>
    public static IReadOnlyList<SourceFile> Enumerate(DirectoryScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        try
        {
            return EnumerateCore(options);
        }
        catch (GlobParseException exception)
        {
            string context = options.IgnoreFilePaths.Count == 1
                ? $" in '{options.IgnoreFilePaths[0]}'"
                : string.Empty;
            throw new InvalidDataException($"invalid ignore pattern{context}: {exception.Message}", exception);
        }
    }

    private static List<SourceFile> EnumerateCore(DirectoryScanOptions options)
    {
        if (IsCancellationRequested(options))
        {
            return [];
        }

        if (File.Exists(options.Root))
        {
            return EnumerateSingleFile(options);
        }

        if (!Directory.Exists(options.Root))
        {
            throw new DirectoryNotFoundException(options.Root);
        }

        var sourceFiles = new List<SourceFile>();
        Dictionary<string, bool>? pathAllowlistCache = options.IsPathAllowed is null
            ? null
            : new Dictionary<string, bool>(StringComparer.Ordinal);
        HashSet<string>? yieldedFileSymlinkPaths = ShouldSupplementFileSymlinks(options)
            ? new HashSet<string>(PathComparer)
            : null;
        var walker = new FileWalker(CreateWalkerOptions(options));
        foreach (FileWalkEntry entry in walker.Enumerate(options.Root))
        {
            if (IsCancellationRequested(options))
            {
                break;
            }

            string scanFullPath = entry.FullPath;
            bool resolvedFileSymlink = false;
            if (!entry.IsFile)
            {
                if (!options.FollowSymbolicLinks || !TryResolveSymlinkFile(entry.FullPath, out scanFullPath))
                {
                    continue;
                }

                resolvedFileSymlink = true;
            }

            string displayPath = CreateDisplayPath(options, entry.FullPath);
            string symlinkDisplayPath = string.Empty;
            if (IsPathOrAncestorAllowed(options.IsPathAllowed, pathAllowlistCache, displayPath))
            {
                continue;
            }

            if (resolvedFileSymlink || entry.IsSymbolicLink)
            {
                if (!options.FollowSymbolicLinks)
                {
                    continue;
                }

                if (!resolvedFileSymlink && !TryResolveSymlinkFile(entry.FullPath, out scanFullPath))
                {
                    continue;
                }

                symlinkDisplayPath = displayPath;
                if (!IsPathWithinRoot(options.Root, scanFullPath))
                {
                    continue;
                }

                displayPath = CreateDisplayPath(options, scanFullPath);
            }
            else if (options.FollowSymbolicLinks
                && !TryResolveFollowedFile(options, entry.FullPath, displayPath, out scanFullPath, out displayPath, out symlinkDisplayPath))
            {
                continue;
            }

            if (symlinkDisplayPath.Length != 0)
            {
                yieldedFileSymlinkPaths?.Add(Path.GetFullPath(entry.FullPath));
            }

            AddSourceFile(sourceFiles, options, scanFullPath, displayPath, symlinkDisplayPath);
        }

        if (yieldedFileSymlinkPaths is not null)
        {
            AddMissingFileSymlinks(sourceFiles, options, pathAllowlistCache, yieldedFileSymlinkPaths);
        }

        return sourceFiles;
    }

    private static List<SourceFile> EnumerateSingleFile(DirectoryScanOptions options)
    {
        if (IsCancellationRequested(options))
        {
            return [];
        }

        FileInfo fileInfo = new(options.Root);
        if (options.MaxTargetBytes.HasValue && fileInfo.Length > options.MaxTargetBytes.Value)
        {
            return [];
        }

        var sourceFiles = new List<SourceFile>();
        string displayPath = CreateDisplayPath(options, options.Root);
        if (!IsPathAllowed(options.IsPathAllowed, displayPath))
        {
            string scanFullPath = options.Root;
            string symlinkDisplayPath = string.Empty;
            if (IsSymbolicLink(fileInfo))
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
        if (IsCancellationRequested(options))
        {
            return;
        }

        if (ArchiveReader.IsArchiveFile(fullPath, options.IdentifyArchivesByContent))
        {
            if (options.MaxArchiveDepth > 0)
            {
                var entries = new List<ArchiveEntry>();
                if (ArchiveReader.TryReadFileEntries(
                    fullPath,
                    displayPath,
                    options.MaxArchiveDepth,
                    options.MaxArchiveEntries,
                    options.MaxArchiveBytes,
                    options.MaxArchiveCompressionRatio,
                    options.MaxTargetBytes,
                    options.IsPathAllowed,
                    options.WarningSink,
                    options.IsCancellationRequested,
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

    private static string CreateDisplayPath(DirectoryScanOptions options, string fullPath)
    {
        string displayPath;
        if (!options.PreserveSourcePaths)
        {
            displayPath = File.Exists(options.Root)
                ? Path.GetFileName(fullPath)
                : Path.GetRelativePath(options.Root, fullPath);
        }
        else if (options.SourcePathIsFullyQualified)
        {
            displayPath = Path.GetFullPath(fullPath);
        }
        else
        {
            displayPath = Path.GetRelativePath(Environment.CurrentDirectory, fullPath);
        }

        return displayPath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }

    private static bool IsSymbolicLink(FileSystemInfo fileSystemInfo)
    {
        return TryResolveLinkTarget(fileSystemInfo) is not null
            || (fileSystemInfo.Attributes & FileAttributes.ReparsePoint) != 0;
    }

    private static bool TryResolveSymlinkFile(string path, out string fullPath)
    {
        FileSystemInfo? target = TryResolveLinkTarget(new FileInfo(path));
        if (target is not null && File.Exists(target.FullName))
        {
            fullPath = target.FullName;
            return true;
        }

        fullPath = string.Empty;
        return false;
    }

    private static FileSystemInfo? TryResolveLinkTarget(FileSystemInfo fileSystemInfo)
    {
        if (UnixSymbolicLink.TryResolveFinalTarget(fileSystemInfo.FullName, out string nativeTargetPath))
        {
            return Directory.Exists(nativeTargetPath)
                ? new DirectoryInfo(nativeTargetPath)
                : new FileInfo(nativeTargetPath);
        }

        try
        {
            FileSystemInfo? target = fileSystemInfo.ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null)
            {
                return target;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    private static bool ShouldSupplementFileSymlinks(DirectoryScanOptions options)
    {
        return options.FollowSymbolicLinks
            && !options.IgnoreHidden
            && !options.ReadPicketIgnoreFiles
            && !options.ReadIgnoreFiles
            && !options.ReadGitIgnoreFiles
            && !options.ReadGlobalGitIgnore
            && !options.ReadParentIgnoreFiles
            && options.IgnoreFilePaths.Count == 0;
    }

    private static void AddMissingFileSymlinks(
        List<SourceFile> sourceFiles,
        DirectoryScanOptions options,
        Dictionary<string, bool>? pathAllowlistCache,
        HashSet<string> yieldedFileSymlinkPaths)
    {
        foreach (string symlinkPath in EnumerateFollowedFileSymlinkPaths(options))
        {
            if (yieldedFileSymlinkPaths.Contains(symlinkPath)
                || !TryResolveSymlinkFile(symlinkPath, out string targetPath)
                || !IsPathWithinRoot(options.Root, targetPath))
            {
                continue;
            }

            string symlinkDisplayPath = CreateDisplayPath(options, symlinkPath);
            if (IsPathOrAncestorAllowed(options.IsPathAllowed, pathAllowlistCache, symlinkDisplayPath)
                || (options.MaxTargetBytes.HasValue && new FileInfo(targetPath).Length > options.MaxTargetBytes.Value))
            {
                continue;
            }

            var supplementalFiles = new List<SourceFile>();
            AddSourceFile(
                supplementalFiles,
                options,
                targetPath,
                CreateDisplayPath(options, targetPath),
                symlinkDisplayPath);
            if (supplementalFiles.Count == 0)
            {
                continue;
            }

            int insertionIndex = sourceFiles.FindIndex(file => StringComparer.Ordinal.Compare(
                GetTraversalDisplayPath(file),
                symlinkDisplayPath) > 0);
            if (insertionIndex < 0)
            {
                sourceFiles.AddRange(supplementalFiles);
            }
            else
            {
                sourceFiles.InsertRange(insertionIndex, supplementalFiles);
            }

            yieldedFileSymlinkPaths.Add(symlinkPath);
        }
    }

    private static List<string> EnumerateFollowedFileSymlinkPaths(DirectoryScanOptions options)
    {
        string rootPath = Path.GetFullPath(options.Root);
        FileSystemInfo? rootTarget = TryResolveLinkTarget(new DirectoryInfo(rootPath));
        string canonicalRoot = rootTarget?.FullName ?? rootPath;
        var rootAncestors = new HashSet<string>(PathComparer)
        {
            canonicalRoot,
        };
        var pending = new Stack<(string TraversalPath, string CanonicalPath, HashSet<string> Ancestors)>();
        pending.Push((rootPath, canonicalRoot, rootAncestors));
        var symlinkPaths = new List<string>();
        while (pending.TryPop(out (string TraversalPath, string CanonicalPath, HashSet<string> Ancestors) current))
        {
            if (IsCancellationRequested(options))
            {
                break;
            }

            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(current.TraversalPath);
            }
            catch (Exception ex) when (ex is DirectoryNotFoundException or IOException or UnauthorizedAccessException)
            {
                continue;
            }

            Array.Sort(entries, StringComparer.Ordinal);
            for (int index = entries.Length - 1; index >= 0; index--)
            {
                string entryPath = entries[index];
                FileSystemInfo entryInfo = Directory.Exists(entryPath) && !File.Exists(entryPath)
                    ? new DirectoryInfo(entryPath)
                    : new FileInfo(entryPath);
                FileSystemInfo? target = TryResolveLinkTarget(entryInfo);
                if (target is not null && File.Exists(target.FullName))
                {
                    if (IsPathWithinRoot(options.Root, target.FullName))
                    {
                        symlinkPaths.Add(Path.GetFullPath(entryPath));
                    }

                    continue;
                }

                bool isDirectory = target is not null
                    ? Directory.Exists(target.FullName)
                    : Directory.Exists(entryPath);
                if (!isDirectory)
                {
                    continue;
                }

                string canonicalPath = target?.FullName ?? Path.Combine(current.CanonicalPath, Path.GetFileName(entryPath));
                if (!IsPathWithinRoot(options.Root, canonicalPath) || current.Ancestors.Contains(canonicalPath))
                {
                    continue;
                }

                var childAncestors = new HashSet<string>(current.Ancestors, PathComparer)
                {
                    canonicalPath,
                };
                pending.Push((entryPath, canonicalPath, childAncestors));
            }
        }

        symlinkPaths.Sort(StringComparer.Ordinal);
        return symlinkPaths;
    }

    private static string GetTraversalDisplayPath(SourceFile file)
    {
        return file.SymlinkDisplayPath.Length == 0 ? file.DisplayPath : file.SymlinkDisplayPath;
    }

    private static bool TryResolveFollowedFile(
        DirectoryScanOptions options,
        string fullPath,
        string originalDisplayPath,
        out string resolvedFullPath,
        out string displayPath,
        out string symlinkDisplayPath)
    {
        resolvedFullPath = fullPath;
        displayPath = originalDisplayPath;
        symlinkDisplayPath = string.Empty;
        if (!TryResolvePathThroughSymlinks(options.Root, fullPath, out string finalPath))
        {
            return false;
        }

        if (AreSamePath(fullPath, finalPath))
        {
            return true;
        }

        if (!IsPathWithinRoot(options.Root, finalPath))
        {
            return false;
        }

        resolvedFullPath = finalPath;
        displayPath = CreateDisplayPath(options, finalPath);
        symlinkDisplayPath = originalDisplayPath;
        return true;
    }

    private static bool TryResolvePathThroughSymlinks(string rootPath, string path, out string resolvedPath)
    {
        try
        {
            string fullRootPath = Path.GetFullPath(rootPath);
            string fullPath = Path.GetFullPath(path);
            if (!IsPathWithinRoot(fullRootPath, fullPath))
            {
                resolvedPath = string.Empty;
                return false;
            }

            string current = fullRootPath;
            string relativePath = Path.GetRelativePath(fullRootPath, fullPath);
            string[] parts = relativePath.Split(s_pathSeparators, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                current = Path.Combine(current, parts[i]);
                bool isLastPart = i == parts.Length - 1;
                FileSystemInfo pathInfo = isLastPart ? new FileInfo(current) : new DirectoryInfo(current);
                if (!IsSymbolicLink(pathInfo))
                {
                    continue;
                }

                FileSystemInfo? target = TryResolveLinkTarget(pathInfo);
                if (target is null)
                {
                    resolvedPath = string.Empty;
                    return false;
                }

                current = Path.GetFullPath(target.FullName);
            }

            resolvedPath = current;
            return File.Exists(resolvedPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            resolvedPath = string.Empty;
            return false;
        }
    }

    private static bool AreSamePath(string first, string second)
    {
        return Path.GetFullPath(first).Equals(Path.GetFullPath(second), PathComparison);
    }

    private static bool IsPathOrAncestorAllowed(
        Func<string, bool>? isPathAllowed,
        Dictionary<string, bool>? pathAllowlistCache,
        string displayPath)
    {
        if (isPathAllowed is null || pathAllowlistCache is null)
        {
            return false;
        }

        if (isPathAllowed(displayPath))
        {
            return true;
        }

        int separatorIndex = displayPath.LastIndexOf('/');
        return separatorIndex > 0
            && IsDirectoryOrAncestorAllowed(isPathAllowed, pathAllowlistCache, displayPath[..separatorIndex]);
    }

    private static bool IsDirectoryOrAncestorAllowed(
        Func<string, bool> isPathAllowed,
        Dictionary<string, bool> pathAllowlistCache,
        string directoryPath)
    {
        if (pathAllowlistCache.TryGetValue(directoryPath, out bool allowed))
        {
            return allowed;
        }

        allowed = isPathAllowed(directoryPath);
        int separatorIndex = directoryPath.LastIndexOf('/');
        if (!allowed && separatorIndex > 0)
        {
            allowed = IsDirectoryOrAncestorAllowed(
                isPathAllowed,
                pathAllowlistCache,
                directoryPath[..separatorIndex]);
        }

        pathAllowlistCache.Add(directoryPath, allowed);
        return allowed;
    }

    private static bool IsPathAllowed(Func<string, bool>? isPathAllowed, string displayPath)
    {
        return isPathAllowed is not null && isPathAllowed(displayPath);
    }

    private static bool IsPathWithinRoot(string root, string path)
    {
        string fullRoot;
        string fullPath;
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            if (!UnixSymbolicLink.TryCanonicalizeExistingPath(root, out fullRoot)
                || !UnixSymbolicLink.TryCanonicalizeExistingPath(path, out fullPath))
            {
                return false;
            }
        }
        else
        {
            fullRoot = Path.GetFullPath(root);
            fullPath = Path.GetFullPath(path);
        }

        fullRoot = EnsureTrailingDirectorySeparator(fullRoot);
        return fullPath.StartsWith(fullRoot, PathComparison);
    }

    private static string EnsureTrailingDirectorySeparator(string path)
    {
        return Path.EndsInDirectorySeparator(path)
            ? path
            : string.Concat(path, Path.DirectorySeparatorChar);
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static StringComparer PathComparer => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    private static bool IsCancellationRequested(DirectoryScanOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }
}
