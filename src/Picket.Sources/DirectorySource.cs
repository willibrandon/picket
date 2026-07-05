using System.IO.Compression;
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
        if (IsZipFile(fullPath))
        {
            if (options.MaxArchiveDepth > 0)
            {
                TryAddZipArchiveEntries(sourceFiles, options, fullPath, displayPath, archiveDepth: 0);
            }

            return;
        }

        sourceFiles.Add(new SourceFile(fullPath, displayPath));
    }

    private static bool TryAddZipArchiveEntries(
        List<SourceFile> sourceFiles,
        DirectoryScanOptions options,
        string fullPath,
        string displayPath,
        int archiveDepth)
    {
        if (archiveDepth + 1 > options.MaxArchiveDepth || !IsZipFile(fullPath))
        {
            return false;
        }

        try
        {
            using FileStream stream = File.OpenRead(fullPath);
            AddZipArchiveEntries(sourceFiles, options, fullPath, displayPath, stream, archiveDepth + 1);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void AddZipArchiveEntries(
        List<SourceFile> sourceFiles,
        DirectoryScanOptions options,
        string fullPath,
        string displayPath,
        Stream stream,
        int archiveDepth)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (IsDirectoryEntry(entry) || IsTooLarge(entry, options.MaxTargetBytes))
            {
                continue;
            }

            string normalizedEntryPath = NormalizeArchiveEntryPath(entry.FullName);
            if (normalizedEntryPath.Length == 0)
            {
                continue;
            }

            string entryDisplayPath = $"{displayPath}!{normalizedEntryPath}";
            byte[] content = ReadEntryBytes(entry);
            if (IsZipContent(content))
            {
                if (archiveDepth >= options.MaxArchiveDepth)
                {
                    continue;
                }

                using var innerStream = new MemoryStream(content, writable: false);
                try
                {
                    AddZipArchiveEntries(sourceFiles, options, fullPath, entryDisplayPath, innerStream, archiveDepth + 1);
                    continue;
                }
                catch (InvalidDataException)
                {
                    // Fall through and scan corrupt zip-like entries as regular files.
                }
            }

            sourceFiles.Add(new SourceFile(fullPath, entryDisplayPath, content));
        }
    }

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using Stream stream = entry.Open();
        int capacity = entry.Length is > 0 and <= int.MaxValue ? (int)entry.Length : 0;
        using var memoryStream = new MemoryStream(capacity);
        stream.CopyTo(memoryStream);
        return memoryStream.ToArray();
    }

    private static bool IsDirectoryEntry(ZipArchiveEntry entry)
    {
        return entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\');
    }

    private static bool IsTooLarge(ZipArchiveEntry entry, long? maxTargetBytes)
    {
        return maxTargetBytes.HasValue && entry.Length > maxTargetBytes.Value;
    }

    private static bool IsZipFile(string path)
    {
        try
        {
            using FileStream stream = File.OpenRead(path);
            Span<byte> header = stackalloc byte[4];
            int read = stream.Read(header);
            return read >= 4 && IsZipHeader(header);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsZipContent(ReadOnlySpan<byte> content)
    {
        return content.Length >= 4 && IsZipHeader(content[..4]);
    }

    private static bool IsZipHeader(ReadOnlySpan<byte> header)
    {
        if (header[0] != (byte)'P' || header[1] != (byte)'K')
        {
            return false;
        }

        return header[2] switch
        {
            0x03 => header[3] == 0x04,
            0x05 => header[3] == 0x06,
            0x07 => header[3] == 0x08,
            _ => false,
        };
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

    private static string NormalizeArchiveEntryPath(string value)
    {
        string normalized = value.Replace('\\', '/');
        while (normalized.StartsWith('/'))
        {
            normalized = normalized[1..];
        }

        return normalized;
    }
}
