namespace Picket.Sources;

/// <summary>
/// Configures compatibility-mode directory enumeration.
/// </summary>
/// <param name="root">The directory or file path to enumerate.</param>
/// <param name="maxTargetBytes">The maximum file size to yield, or <see langword="null" /> for no cap.</param>
public sealed class DirectoryScanOptions(string root, long? maxTargetBytes = null)
{
    /// <summary>
    /// Gets the full root path to enumerate.
    /// </summary>
    public string Root { get; } = Path.GetFullPath(RequireRoot(root));

    /// <summary>
    /// Gets the maximum file size to yield, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxTargetBytes { get; } = RequireMaxTargetBytes(maxTargetBytes);

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
