namespace Picket.Sources;

/// <summary>
/// Represents an added git patch fragment selected for compatibility-mode scanning.
/// </summary>
/// <param name="input">The added patch bytes.</param>
/// <param name="filePath">The normalized file path.</param>
/// <param name="startLine">The one-based line where the fragment starts in the new file.</param>
/// <param name="commit">The git commit SHA, or an empty string for working tree diffs.</param>
/// <param name="author">The git author name, or an empty string.</param>
/// <param name="email">The git author email, or an empty string.</param>
/// <param name="date">The git author date in RFC 3339 UTC form, or an empty string.</param>
/// <param name="message">The git commit message, or an empty string.</param>
public sealed class GitPatchFragment(
    ReadOnlyMemory<byte> input,
    string filePath,
    int startLine,
    string commit = "",
    string author = "",
    string email = "",
    string date = "",
    string message = "")
{
    /// <summary>
    /// Gets the added patch bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Input { get; } = input;

    /// <summary>
    /// Gets the normalized file path.
    /// </summary>
    public string FilePath { get; } = NormalizePath(RequireText(filePath));

    /// <summary>
    /// Gets the one-based line where the fragment starts in the new file.
    /// </summary>
    public int StartLine { get; } = RequireStartLine(startLine);

    /// <summary>
    /// Gets the git commit SHA, or an empty string for working tree diffs.
    /// </summary>
    public string Commit { get; } = commit ?? string.Empty;

    /// <summary>
    /// Gets the git author name, or an empty string.
    /// </summary>
    public string Author { get; } = author ?? string.Empty;

    /// <summary>
    /// Gets the git author email, or an empty string.
    /// </summary>
    public string Email { get; } = email ?? string.Empty;

    /// <summary>
    /// Gets the git author date in RFC 3339 UTC form, or an empty string.
    /// </summary>
    public string Date { get; } = date ?? string.Empty;

    /// <summary>
    /// Gets the git commit message, or an empty string.
    /// </summary>
    public string Message { get; } = message ?? string.Empty;

    private static string RequireText(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int RequireStartLine(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static string NormalizePath(string value)
    {
        return value.Replace('\\', '/');
    }
}
