namespace Picket.Sources;

/// <summary>
/// Configures compatibility-mode directory enumeration.
/// </summary>
/// <param name="root">The directory or file path to enumerate.</param>
/// <param name="maxTargetBytes">The maximum file size to yield, or <see langword="null" /> for no cap.</param>
/// <param name="followSymbolicLinks">A value indicating whether symbolic links are followed.</param>
public sealed class DirectoryScanOptions(string root, long? maxTargetBytes = null, bool followSymbolicLinks = false)
{
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
}
