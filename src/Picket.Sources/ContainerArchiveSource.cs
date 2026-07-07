namespace Picket.Sources;

/// <summary>
/// Enumerates local Docker and OCI image archives as native source files.
/// </summary>
public static class ContainerArchiveSource
{
    /// <summary>
    /// Enumerates files from a local container image archive.
    /// </summary>
    /// <param name="archivePath">The Docker or OCI image archive path.</param>
    /// <param name="displayPrefix">The report display prefix, such as <c>docker-archive</c> or <c>oci-archive</c>.</param>
    /// <param name="maxArchiveDepth">The maximum archive depth for archive content inside the image envelope.</param>
    /// <param name="maxArchiveEntries">The maximum number of archive entries to read.</param>
    /// <param name="maxArchiveBytes">The maximum decompressed archive byte budget.</param>
    /// <param name="maxArchiveCompressionRatio">The maximum archive expansion ratio.</param>
    /// <param name="maxTargetBytes">The maximum bytes allowed for each yielded target file.</param>
    /// <param name="isPathAllowed">A predicate that returns <see langword="true" /> when a global path allowlist should skip the path.</param>
    /// <param name="warningSink">An optional warning sink for archive safety messages.</param>
    /// <param name="isCancellationRequested">An optional cancellation predicate.</param>
    /// <returns>The source files selected from the container archive.</returns>
    public static List<SourceFile> Enumerate(
        string archivePath,
        string displayPrefix,
        int maxArchiveDepth,
        int maxArchiveEntries,
        long? maxArchiveBytes,
        int maxArchiveCompressionRatio,
        long? maxTargetBytes,
        Func<string, bool>? isPathAllowed = null,
        Action<string>? warningSink = null,
        Func<bool>? isCancellationRequested = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayPrefix);

        if (maxArchiveDepth <= 0)
        {
            return [];
        }

        string fullPath = Path.GetFullPath(archivePath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Container archive was not found.", fullPath);
        }

        var entries = new List<ArchiveEntry>();
        int effectiveMaxArchiveDepth = maxArchiveDepth == int.MaxValue ? int.MaxValue : maxArchiveDepth + 1;
        string displayPath = CreateArchiveDisplayPath(fullPath, displayPrefix);
        if (!ArchiveReader.TryReadFileEntries(
            fullPath,
            displayPath,
            effectiveMaxArchiveDepth,
            maxArchiveEntries,
            maxArchiveBytes,
            maxArchiveCompressionRatio,
            maxTargetBytes,
            isPathAllowed,
            warningSink,
            isCancellationRequested,
            entries))
        {
            throw new InvalidOperationException($"Container archive '{archivePath}' could not be read as a supported archive.");
        }

        var files = new List<SourceFile>(entries.Count);
        foreach (ArchiveEntry entry in entries)
        {
            files.Add(new SourceFile(fullPath, entry.DisplayPath, entry.Content));
        }

        return files;
    }

    private static string CreateArchiveDisplayPath(string fullPath, string displayPrefix)
    {
        string fileName = Path.GetFileName(fullPath);
        return string.Concat(displayPrefix, "/", fileName).Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }
}
