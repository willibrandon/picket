namespace Picket.Sources;

/// <summary>
/// Configures native enumeration of staged, unstaged, and untracked Git changes.
/// </summary>
/// <param name="root">The repository path, nested path, or file to enumerate.</param>
/// <param name="maxTargetBytes">The maximum raw source size to yield, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth to enumerate.</param>
/// <param name="maxArchiveEntries">The maximum number of archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="maxArchiveCompressionRatio">The maximum archive expansion ratio, or 0 for no cap.</param>
/// <param name="respectGitIgnoreFiles">A value indicating whether Git-ignored untracked files are excluded.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> for globally allowlisted paths.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source warnings.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
public sealed class GitWorkingTreeScanOptions(
    string root,
    long? maxTargetBytes = null,
    int maxArchiveDepth = 0,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    bool respectGitIgnoreFiles = true,
    Func<string, bool>? isPathAllowed = null,
    Action<string>? warningSink = null,
    Func<bool>? isCancellationRequested = null)
{
    /// <summary>
    /// Gets the full selected path.
    /// </summary>
    public string Root { get; } = Path.GetFullPath(RequireRoot(root));

    /// <summary>
    /// Gets the maximum raw source size to yield, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxTargetBytes { get; } = RequireMaxTargetBytes(maxTargetBytes);

    /// <summary>
    /// Gets the maximum nested archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireNonNegative(maxArchiveDepth, nameof(maxArchiveDepth));

    /// <summary>
    /// Gets the maximum number of archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireNonNegative(maxArchiveEntries, nameof(maxArchiveEntries));

    /// <summary>
    /// Gets the maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireNonNegative(
        maxArchiveCompressionRatio,
        nameof(maxArchiveCompressionRatio));

    internal bool RespectGitIgnoreFiles { get; } = respectGitIgnoreFiles;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    private static string RequireRoot(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static long? RequireMaxTargetBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    private static long? RequireMaxArchiveBytes(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }

    private static int RequireNonNegative(int value, string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value, parameterName);
        return value;
    }
}
