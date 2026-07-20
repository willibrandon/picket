namespace Picket.Sources;

/// <summary>
/// Configures compatibility-mode git patch enumeration.
/// </summary>
/// <param name="root">The git repository path.</param>
/// <param name="logOptions">Optional raw git log options split the same way as Gitleaks.</param>
/// <param name="staged">A value indicating whether staged changes are scanned with <c>git diff --staged</c>.</param>
/// <param name="preCommit">A value indicating whether working tree changes are scanned with <c>git diff</c>.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth to enumerate.</param>
/// <param name="maxTargetBytes">The maximum archive entry size to yield, or <see langword="null" /> for no cap.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> for globally allowlisted archive entry paths.</param>
/// <param name="maxArchiveEntries">The maximum number of archive entries to enumerate, or 0 for no cap.</param>
/// <param name="maxArchiveBytes">The maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
/// <param name="maxArchiveCompressionRatio">The maximum archive expansion ratio, or 0 for no cap.</param>
/// <param name="isCancellationRequested">An optional predicate that stops enumeration when it returns <see langword="true" />.</param>
/// <param name="identifyArchivesByContent">A value indicating whether binary archives are identified from content instead of Gitleaks-compatible path names.</param>
public sealed class GitScanOptions(
    string root,
    string? logOptions = null,
    bool staged = false,
    bool preCommit = false,
    int maxArchiveDepth = 0,
    long? maxTargetBytes = null,
    Func<string, bool>? isPathAllowed = null,
    int maxArchiveEntries = ArchiveScanDefaults.DefaultMaxEntries,
    long? maxArchiveBytes = ArchiveScanDefaults.DefaultMaxBytes,
    Action<string>? warningSink = null,
    int maxArchiveCompressionRatio = ArchiveScanDefaults.DefaultMaxCompressionRatio,
    Func<bool>? isCancellationRequested = null,
    bool identifyArchivesByContent = false)
{
    /// <summary>
    /// Gets the full git repository path.
    /// </summary>
    public string Root { get; } = Path.GetFullPath(RequireRoot(root));

    /// <summary>
    /// Gets the optional raw git log options split the same way as Gitleaks.
    /// </summary>
    public string LogOptions { get; } = logOptions ?? string.Empty;

    /// <summary>
    /// Gets a value indicating whether staged changes are scanned with <c>git diff --staged</c>.
    /// </summary>
    public bool Staged { get; } = staged;

    /// <summary>
    /// Gets a value indicating whether working tree changes are scanned with <c>git diff</c>.
    /// </summary>
    public bool PreCommit { get; } = preCommit;

    /// <summary>
    /// Gets the maximum nested archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets the maximum number of decompressed archive bytes to enumerate, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxArchiveBytes { get; } = RequireMaxArchiveBytes(maxArchiveBytes);

    /// <summary>
    /// Gets the maximum archive expansion ratio, or 0 for no cap.
    /// </summary>
    public int MaxArchiveCompressionRatio { get; } = RequireMaxArchiveCompressionRatio(maxArchiveCompressionRatio);

    /// <summary>
    /// Gets the maximum archive entry size to yield, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxTargetBytes { get; } = RequireMaxTargetBytes(maxTargetBytes);

    /// <summary>
    /// Gets a value indicating whether binary archives are identified from content instead of Gitleaks-compatible path names.
    /// </summary>
    public bool IdentifyArchivesByContent { get; } = identifyArchivesByContent;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

    internal Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    private static string RequireRoot(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int RequireMaxArchiveDepth(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static int RequireMaxArchiveEntries(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
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

    private static int RequireMaxArchiveCompressionRatio(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
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
}
