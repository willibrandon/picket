namespace Picket.Sources;

/// <summary>
/// Represents a source file selected for scanning.
/// </summary>
/// <param name="fullPath">The full filesystem path.</param>
/// <param name="displayPath">The normalized path used in reports and fingerprints.</param>
public sealed class SourceFile(string fullPath, string displayPath)
{
    private readonly byte[]? _content;

    internal SourceFile(string fullPath, string displayPath, byte[] content)
        : this(fullPath, displayPath)
    {
        _content = content ?? throw new ArgumentNullException(nameof(content));
    }

    /// <summary>
    /// Gets the full filesystem path.
    /// </summary>
    public string FullPath { get; } = Path.GetFullPath(RequireText(fullPath));

    /// <summary>
    /// Gets the normalized path used in reports and fingerprints.
    /// </summary>
    public string DisplayPath { get; } = NormalizeDisplayPath(displayPath);

    /// <summary>
    /// Reads all bytes for this source file.
    /// </summary>
    /// <returns>The source content bytes.</returns>
    public byte[] ReadAllBytes()
    {
        return _content is null ? File.ReadAllBytes(FullPath) : _content;
    }

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
