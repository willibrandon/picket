namespace Picket.Sources;

/// <summary>
/// Configures compatibility-mode git patch enumeration.
/// </summary>
/// <param name="root">The git repository path.</param>
/// <param name="logOptions">Optional raw git log options split the same way as Gitleaks.</param>
/// <param name="staged">A value indicating whether staged changes are scanned with <c>git diff --staged</c>.</param>
/// <param name="preCommit">A value indicating whether working tree changes are scanned with <c>git diff</c>.</param>
public sealed class GitScanOptions(
    string root,
    string? logOptions = null,
    bool staged = false,
    bool preCommit = false)
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

    private static string RequireRoot(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }
}
