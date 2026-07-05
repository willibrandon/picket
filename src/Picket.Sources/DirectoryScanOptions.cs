namespace Picket.Sources;

/// <summary>
/// Configures compatibility-mode directory enumeration.
/// </summary>
/// <param name="root">The directory or file path to enumerate.</param>
/// <param name="maxTargetBytes">The maximum file size to yield, or <see langword="null" /> for no cap.</param>
/// <param name="followSymbolicLinks">A value indicating whether symbolic links are followed.</param>
/// <param name="maxArchiveDepth">The maximum nested archive depth to enumerate.</param>
/// <param name="isPathAllowed">An optional predicate that returns <see langword="true" /> for globally allowlisted paths.</param>
/// <param name="readPicketIgnoreFiles">A value indicating whether per-directory <c>.picketignore</c> files are read.</param>
/// <param name="readIgnoreFiles">A value indicating whether Scout-supported <c>.ignore</c>, <c>.rgignore</c>, and <c>.scoutignore</c> files are read.</param>
/// <param name="readGitIgnoreFiles">A value indicating whether Git ignore files are read.</param>
/// <param name="readGlobalGitIgnore">A value indicating whether the configured global Git ignore file is read.</param>
/// <param name="ignoreHidden">A value indicating whether hidden files and directories are ignored.</param>
/// <param name="readParentIgnoreFiles">A value indicating whether ignore files from parent directories above the root are read.</param>
/// <param name="ignoreFilePaths">Explicit ignore files to apply while traversing.</param>
/// <param name="maxArchiveEntries">The maximum number of archive entries to enumerate, or 0 for no cap.</param>
/// <param name="warningSink">An optional callback that receives non-fatal source enumeration warnings.</param>
public sealed class DirectoryScanOptions(
    string root,
    long? maxTargetBytes = null,
    bool followSymbolicLinks = false,
    int maxArchiveDepth = 0,
    Func<string, bool>? isPathAllowed = null,
    bool readPicketIgnoreFiles = false,
    bool readIgnoreFiles = false,
    bool readGitIgnoreFiles = false,
    bool readGlobalGitIgnore = false,
    bool ignoreHidden = false,
    bool readParentIgnoreFiles = false,
    IReadOnlyList<string>? ignoreFilePaths = null,
    int maxArchiveEntries = 0,
    Action<string>? warningSink = null)
{
    private readonly string[] _ignoreFilePaths = RequireIgnoreFilePaths(ignoreFilePaths);

    /// <summary>
    /// Gets the full root path to enumerate.
    /// </summary>
    public string Root { get; } = Path.GetFullPath(RequireRoot(root));

    /// <summary>
    /// Gets the maximum file size to yield, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxTargetBytes { get; } = RequireMaxTargetBytes(maxTargetBytes);

    /// <summary>
    /// Gets a value indicating whether symbolic links are followed.
    /// </summary>
    public bool FollowSymbolicLinks { get; } = followSymbolicLinks;

    /// <summary>
    /// Gets the maximum nested archive depth to enumerate.
    /// </summary>
    public int MaxArchiveDepth { get; } = RequireMaxArchiveDepth(maxArchiveDepth);

    /// <summary>
    /// Gets the maximum number of archive entries to enumerate, or 0 for no cap.
    /// </summary>
    public int MaxArchiveEntries { get; } = RequireMaxArchiveEntries(maxArchiveEntries);

    /// <summary>
    /// Gets a value indicating whether per-directory <c>.picketignore</c> files are read.
    /// </summary>
    public bool ReadPicketIgnoreFiles { get; } = readPicketIgnoreFiles;

    /// <summary>
    /// Gets a value indicating whether Scout-supported <c>.ignore</c>, <c>.rgignore</c>, and <c>.scoutignore</c> files are read.
    /// </summary>
    public bool ReadIgnoreFiles { get; } = readIgnoreFiles;

    /// <summary>
    /// Gets a value indicating whether Git ignore files are read.
    /// </summary>
    public bool ReadGitIgnoreFiles { get; } = readGitIgnoreFiles;

    /// <summary>
    /// Gets a value indicating whether the configured global Git ignore file is read.
    /// </summary>
    public bool ReadGlobalGitIgnore { get; } = readGlobalGitIgnore;

    /// <summary>
    /// Gets a value indicating whether hidden files and directories are ignored.
    /// </summary>
    public bool IgnoreHidden { get; } = ignoreHidden;

    /// <summary>
    /// Gets a value indicating whether ignore files from parent directories above the root are read.
    /// </summary>
    public bool ReadParentIgnoreFiles { get; } = readParentIgnoreFiles;

    /// <summary>
    /// Gets explicit ignore files applied while traversing.
    /// </summary>
    public IReadOnlyList<string> IgnoreFilePaths => _ignoreFilePaths;

    internal Func<string, bool>? IsPathAllowed { get; } = isPathAllowed;

    internal Action<string>? WarningSink { get; } = warningSink;

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

    private static string[] RequireIgnoreFilePaths(IReadOnlyList<string>? value)
    {
        if (value is null || value.Count == 0)
        {
            return [];
        }

        var paths = new string[value.Count];
        for (int i = 0; i < value.Count; i++)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value[i]);
            paths[i] = value[i];
        }

        return paths;
    }
}
