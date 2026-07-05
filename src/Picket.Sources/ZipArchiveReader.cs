using System.IO.Compression;

namespace Picket.Sources;

internal static class ZipArchiveReader
{
    internal static bool IsZipFile(string path)
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

    internal static bool IsZipContent(ReadOnlySpan<byte> content)
    {
        return content.Length >= 4 && IsZipHeader(content[..4]);
    }

    internal static bool TryReadFileEntries(
        string fullPath,
        string displayPath,
        int maxArchiveDepth,
        long? maxEntryBytes,
        List<ArchiveEntry> entries)
    {
        if (maxArchiveDepth <= 0 || !IsZipFile(fullPath))
        {
            return false;
        }

        try
        {
            using FileStream stream = File.OpenRead(fullPath);
            AddEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, entries, archiveDepth: 1);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static bool TryReadBytesEntries(
        byte[] content,
        string displayPath,
        int maxArchiveDepth,
        long? maxEntryBytes,
        List<ArchiveEntry> entries)
    {
        if (maxArchiveDepth <= 0 || !IsZipContent(content))
        {
            return false;
        }

        try
        {
            using var stream = new MemoryStream(content, writable: false);
            AddEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, entries, archiveDepth: 1);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static void AddEntries(
        string displayPath,
        Stream stream,
        int maxArchiveDepth,
        long? maxEntryBytes,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (IsDirectoryEntry(entry) || IsTooLarge(entry, maxEntryBytes))
            {
                continue;
            }

            string normalizedEntryPath = NormalizeArchiveEntryPath(entry.FullName);
            if (normalizedEntryPath.Length == 0)
            {
                continue;
            }

            string entryDisplayPath = $"{displayPath}!{normalizedEntryPath}";
            byte[] entryContent = ReadEntryBytes(entry);
            if (IsZipContent(entryContent))
            {
                if (archiveDepth >= maxArchiveDepth)
                {
                    continue;
                }

                using var innerStream = new MemoryStream(entryContent, writable: false);
                try
                {
                    AddEntries(entryDisplayPath, innerStream, maxArchiveDepth, maxEntryBytes, entries, archiveDepth + 1);
                    continue;
                }
                catch (InvalidDataException)
                {
                    // Fall through and scan corrupt zip-like entries as regular files.
                }
            }

            entries.Add(new ArchiveEntry(entryDisplayPath, entryContent));
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

    private static bool IsTooLarge(ZipArchiveEntry entry, long? maxEntryBytes)
    {
        return maxEntryBytes.HasValue && entry.Length > maxEntryBytes.Value;
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
