using System.Buffers;
using System.Formats.Tar;
using System.IO.Compression;

namespace Picket.Sources;

internal static class ArchiveReader
{
    private const int ArchiveKindNone = 0;
    private const int ArchiveKindGzip = 1;
    private const int ArchiveKindTar = 2;
    private const int ArchiveKindZip = 3;
    private const int ArchiveKindZstandard = 4;
    private const int TarMagicOffset = 257;
    private const int TarMagicLength = 5;

    internal static bool IsArchiveFile(string path)
    {
        try
        {
            using FileStream stream = File.OpenRead(path);
            Span<byte> header = stackalloc byte[512];
            int read = stream.Read(header);
            return IdentifyArchiveKind(header[..read]) != ArchiveKindNone;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static bool IsArchiveContent(ReadOnlySpan<byte> content)
    {
        return IdentifyArchiveKind(content) != ArchiveKindNone;
    }

    internal static bool TryReadFileEntries(
        string fullPath,
        string displayPath,
        int maxArchiveDepth,
        int maxArchiveEntries,
        long? maxArchiveBytes,
        int maxArchiveCompressionRatio,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        Action<string>? warningSink,
        Func<bool>? isCancellationRequested,
        List<ArchiveEntry> entries)
    {
        if (maxArchiveDepth <= 0)
        {
            return false;
        }

        try
        {
            using FileStream stream = File.OpenRead(fullPath);
            Span<byte> header = stackalloc byte[512];
            int read = stream.Read(header);
            int archiveKind = IdentifyArchiveKind(header[..read]);
            if (archiveKind == ArchiveKindNone)
            {
                return false;
            }

            stream.Position = 0;
            var budget = new ArchiveReadBudget(maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, isCancellationRequested, warningSink);
            AddEntries(displayPath, stream, archiveKind, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth: 1);
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
        int maxArchiveEntries,
        long? maxArchiveBytes,
        int maxArchiveCompressionRatio,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        Action<string>? warningSink,
        Func<bool>? isCancellationRequested,
        List<ArchiveEntry> entries)
    {
        if (maxArchiveDepth <= 0)
        {
            return false;
        }

        int archiveKind = IdentifyArchiveKind(content);
        if (archiveKind == ArchiveKindNone)
        {
            return false;
        }

        try
        {
            using var stream = new MemoryStream(content, writable: false);
            var budget = new ArchiveReadBudget(maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, isCancellationRequested, warningSink);
            AddEntries(displayPath, stream, archiveKind, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth: 1);
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
        int archiveKind,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        if (!budget.TryContinue(displayPath))
        {
            return;
        }

        switch (archiveKind)
        {
            case ArchiveKindGzip:
                AddGzipEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth);
                break;
            case ArchiveKindTar:
                AddTarEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth);
                break;
            case ArchiveKindZip:
                AddZipEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth);
                break;
            case ArchiveKindZstandard:
                AddZstandardEntries(displayPath, stream, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth);
                break;
        }
    }

    private static void AddZipEntries(
        string displayPath,
        Stream stream,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (!budget.TryContinue(displayPath))
            {
                return;
            }

            if (IsDirectoryEntry(entry) || IsTooLarge(entry.Length, maxEntryBytes))
            {
                continue;
            }

            string normalizedEntryPath = NormalizeArchiveEntryPath(entry.FullName);
            if (normalizedEntryPath.Length == 0)
            {
                continue;
            }

            if (IsPathAllowed(isPathAllowed, normalizedEntryPath))
            {
                continue;
            }

            if (!budget.TryConsumeEntry(displayPath))
            {
                return;
            }

            using Stream entryStream = entry.Open();
            if (!TryReadStreamBytes(displayPath, entryStream, entry.Length, entry.CompressedLength, maxEntryBytes, budget, out byte[] entryContent))
            {
                continue;
            }

            AddEntryOrNestedArchive(
                $"{displayPath}!{normalizedEntryPath}",
                entryContent,
                maxArchiveDepth,
                maxEntryBytes,
                isPathAllowed,
                budget,
                entries,
                archiveDepth);
        }
    }

    private static void AddTarEntries(
        string displayPath,
        Stream stream,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        using var reader = new TarReader(stream, leaveOpen: true);
        TarEntry? entry;
        while ((entry = reader.GetNextEntry()) is not null)
        {
            if (!budget.TryContinue(displayPath))
            {
                return;
            }

            if (entry.DataStream is null || IsTooLarge(entry.Length, maxEntryBytes))
            {
                continue;
            }

            string normalizedEntryPath = NormalizeArchiveEntryPath(entry.Name);
            if (normalizedEntryPath.Length == 0)
            {
                continue;
            }

            if (IsPathAllowed(isPathAllowed, normalizedEntryPath))
            {
                continue;
            }

            if (!budget.TryConsumeEntry(displayPath))
            {
                return;
            }

            if (!TryReadStreamBytes(displayPath, entry.DataStream, entry.Length, compressedLength: null, maxEntryBytes, budget, out byte[] entryContent))
            {
                continue;
            }

            AddEntryOrNestedArchive(
                $"{displayPath}!{normalizedEntryPath}",
                entryContent,
                maxArchiveDepth,
                maxEntryBytes,
                isPathAllowed,
                budget,
                entries,
                archiveDepth);
        }
    }

    private static void AddGzipEntries(
        string displayPath,
        Stream stream,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        if (!budget.TryContinue(displayPath))
        {
            return;
        }

        long? compressedLength = TryGetRemainingLength(stream);
        using var gzipStream = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
        if (!TryReadStreamBytes(
            displayPath,
            gzipStream,
            length: null,
            compressedLength,
            maxEntryBytes,
            budget,
            out byte[] decompressedContent,
            chargeBudgetBytes: false))
        {
            return;
        }

        int innerArchiveKind = IdentifyArchiveKind(decompressedContent);
        if (innerArchiveKind != ArchiveKindNone)
        {
            int innerArchiveDepth = IsCompressedArchiveKind(innerArchiveKind) ? archiveDepth + 1 : archiveDepth;
            if (innerArchiveDepth > maxArchiveDepth)
            {
                return;
            }

            using var innerStream = new MemoryStream(decompressedContent, writable: false);
            AddEntries(displayPath, innerStream, innerArchiveKind, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, innerArchiveDepth);
            return;
        }

        if (!budget.TryConsumeEntry(displayPath)
            || !budget.TryConsumeBytes(displayPath, decompressedContent.Length))
        {
            return;
        }

        entries.Add(new ArchiveEntry(displayPath, decompressedContent));
    }

    private static void AddZstandardEntries(
        string displayPath,
        Stream stream,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        if (!budget.TryContinue(displayPath))
        {
            return;
        }

        long? compressedLength = TryGetRemainingLength(stream);
        using var zstandardStream = new ZstandardDecompressionStream(stream, maxEntryBytes, leaveOpen: true);
        if (!TryReadStreamBytes(
            displayPath,
            zstandardStream,
            length: null,
            compressedLength,
            maxEntryBytes,
            budget,
            out byte[] decompressedContent,
            chargeBudgetBytes: false))
        {
            return;
        }

        int innerArchiveKind = IdentifyArchiveKind(decompressedContent);
        if (innerArchiveKind != ArchiveKindNone)
        {
            int innerArchiveDepth = IsCompressedArchiveKind(innerArchiveKind) ? archiveDepth + 1 : archiveDepth;
            if (innerArchiveDepth > maxArchiveDepth)
            {
                return;
            }

            using var innerStream = new MemoryStream(decompressedContent, writable: false);
            AddEntries(displayPath, innerStream, innerArchiveKind, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, innerArchiveDepth);
            return;
        }

        if (!budget.TryConsumeEntry(displayPath)
            || !budget.TryConsumeBytes(displayPath, decompressedContent.Length))
        {
            return;
        }

        entries.Add(new ArchiveEntry(displayPath, decompressedContent));
    }

    private static void AddEntryOrNestedArchive(
        string entryDisplayPath,
        byte[] entryContent,
        int maxArchiveDepth,
        long? maxEntryBytes,
        Func<string, bool>? isPathAllowed,
        ArchiveReadBudget budget,
        List<ArchiveEntry> entries,
        int archiveDepth)
    {
        if (!budget.TryContinue(entryDisplayPath))
        {
            return;
        }

        int archiveKind = IdentifyArchiveKind(entryContent);
        if (archiveKind == ArchiveKindNone)
        {
            entries.Add(new ArchiveEntry(entryDisplayPath, entryContent));
            return;
        }

        if (archiveDepth >= maxArchiveDepth)
        {
            return;
        }

        using var innerStream = new MemoryStream(entryContent, writable: false);
        try
        {
            AddEntries(entryDisplayPath, innerStream, archiveKind, maxArchiveDepth, maxEntryBytes, isPathAllowed, budget, entries, archiveDepth + 1);
        }
        catch (InvalidDataException)
        {
            entries.Add(new ArchiveEntry(entryDisplayPath, entryContent));
        }
    }

    private static bool TryReadStreamBytes(
        string archivePath,
        Stream stream,
        long? length,
        long? compressedLength,
        long? maxBytes,
        ArchiveReadBudget budget,
        out byte[] bytes,
        bool chargeBudgetBytes = true)
    {
        if (length.HasValue && IsTooLarge(length.Value, maxBytes))
        {
            bytes = [];
            return false;
        }

        int capacity = length is > 0 and <= 81920 ? (int)length.Value : 0;
        using var memoryStream = new MemoryStream(capacity);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        long totalRead = 0;
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (!budget.TryContinue(archivePath))
                {
                    bytes = [];
                    return false;
                }

                totalRead += read;
                if (length.HasValue && totalRead > length.GetValueOrDefault())
                {
                    budget.ReportSizeMetadataMismatch(archivePath, length.Value, totalRead);
                    bytes = [];
                    return false;
                }

                if (IsTooLarge(totalRead, maxBytes)
                    || (compressedLength.HasValue && !budget.TryConsumeCompressionRatio(archivePath, compressedLength.Value, totalRead))
                    || (chargeBudgetBytes
                        ? !budget.TryConsumeBytes(archivePath, read)
                        : !budget.TryCheckBytes(archivePath, totalRead)))
                {
                    bytes = [];
                    return false;
                }

                memoryStream.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        bytes = memoryStream.ToArray();
        return true;
    }

    private static long? TryGetRemainingLength(Stream stream)
    {
        if (!stream.CanSeek)
        {
            return null;
        }

        long length = stream.Length - stream.Position;
        return length < 0 ? 0 : length;
    }

    private static bool IsDirectoryEntry(ZipArchiveEntry entry)
    {
        return entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\');
    }

    private static bool IsTooLarge(long value, long? maxBytes)
    {
        return maxBytes.HasValue && value > maxBytes.Value;
    }

    private static bool IsPathAllowed(Func<string, bool>? isPathAllowed, string path)
    {
        return isPathAllowed is not null && isPathAllowed(path);
    }

    private static int IdentifyArchiveKind(ReadOnlySpan<byte> header)
    {
        if (IsZipHeader(header))
        {
            return ArchiveKindZip;
        }

        if (IsGzipHeader(header))
        {
            return ArchiveKindGzip;
        }

        if (IsZstandardHeader(header))
        {
            return ArchiveKindZstandard;
        }

        return IsTarHeader(header) ? ArchiveKindTar : ArchiveKindNone;
    }

    private static bool IsCompressedArchiveKind(int archiveKind)
    {
        return archiveKind is ArchiveKindGzip or ArchiveKindZstandard;
    }

    private static bool IsZipHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < 4 || header[0] != (byte)'P' || header[1] != (byte)'K')
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

    private static bool IsGzipHeader(ReadOnlySpan<byte> header)
    {
        return header.Length >= 3 && header[0] == 0x1F && header[1] == 0x8B && header[2] == 0x08;
    }

    private static bool IsZstandardHeader(ReadOnlySpan<byte> header)
    {
        return header.Length >= 4
            && header[0] == 0x28
            && header[1] == 0xB5
            && header[2] == 0x2F
            && header[3] == 0xFD;
    }

    private static bool IsTarHeader(ReadOnlySpan<byte> header)
    {
        return header.Length >= TarMagicOffset + TarMagicLength
            && header[TarMagicOffset..(TarMagicOffset + TarMagicLength)].SequenceEqual("ustar"u8);
    }

    private static string NormalizeArchiveEntryPath(string value)
    {
        if (value.Length == 0 || value[0] is '/' or '\\')
        {
            return string.Empty;
        }

        string normalized = value.Replace('\\', '/');
        if (normalized.Length == 0
            || normalized.Contains('\0')
            || normalized.Contains(':')
            || HasUnsafeSegment(normalized))
        {
            return string.Empty;
        }

        return normalized;
    }

    private static bool HasUnsafeSegment(string path)
    {
        int segmentStart = 0;
        for (int i = 0; i <= path.Length; i++)
        {
            if (i != path.Length && path[i] != '/')
            {
                continue;
            }

            int segmentLength = i - segmentStart;
            if (segmentLength == 0
                || (segmentLength == 1 && path[segmentStart] == '.')
                || (segmentLength == 2 && path[segmentStart] == '.' && path[segmentStart + 1] == '.'))
            {
                return true;
            }

            segmentStart = i + 1;
        }

        return false;
    }
}
