namespace Picket.Store;

/// <summary>
/// Describes the current contents of a Picket scan cache.
/// </summary>
/// <param name="rootPath">The cache root path.</param>
/// <param name="entryCount">The number of cache entry files.</param>
/// <param name="currentKeyEntryCount">The number of entries for the active scanner configuration key.</param>
/// <param name="totalBytes">The total size of cache entry files in bytes.</param>
public sealed class PicketScanCacheStats(string rootPath, int entryCount, int currentKeyEntryCount, long totalBytes)
{
    /// <summary>
    /// Gets the cache root path.
    /// </summary>
    public string RootPath { get; } = RequireRootPath(rootPath);

    /// <summary>
    /// Gets the number of cache entry files.
    /// </summary>
    public int EntryCount { get; } = RequireNonNegative(entryCount);

    /// <summary>
    /// Gets the number of entries for the active scanner configuration key.
    /// </summary>
    public int CurrentKeyEntryCount { get; } = RequireNonNegative(currentKeyEntryCount);

    /// <summary>
    /// Gets the total size of cache entry files in bytes.
    /// </summary>
    public long TotalBytes { get; } = RequireNonNegative(totalBytes);

    private static string RequireRootPath(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int RequireNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static long RequireNonNegative(long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }
}
