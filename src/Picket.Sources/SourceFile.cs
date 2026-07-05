namespace Picket.Sources;

/// <summary>
/// Represents a source file selected for scanning.
/// </summary>
/// <param name="fullPath">The full filesystem path.</param>
/// <param name="displayPath">The normalized path used in reports and fingerprints.</param>
public sealed class SourceFile(string fullPath, string displayPath)
{
    /// <summary>
    /// Gets the full filesystem path.
    /// </summary>
    public string FullPath { get; } = Path.GetFullPath(RequireText(fullPath));

    /// <summary>
    /// Gets the normalized path used in reports and fingerprints.
    /// </summary>
    public string DisplayPath { get; } = NormalizeDisplayPath(displayPath);

    private static string RequireText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static string NormalizeDisplayPath(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }
}
