namespace Picket.Engine;

/// <summary>
/// Represents a detected secret finding using the Gitleaks-compatible field model.
/// </summary>
/// <param name="ruleID">The rule identifier.</param>
/// <param name="description">The rule description.</param>
/// <param name="startLine">The one-based start line.</param>
/// <param name="endLine">The one-based end line.</param>
/// <param name="startColumn">The one-based start column.</param>
/// <param name="endColumn">The one-based end column.</param>
/// <param name="match">The full matched text.</param>
/// <param name="secret">The secret text.</param>
/// <param name="file">The logical file path.</param>
/// <param name="symlinkFile">The symlink path, or an empty string.</param>
/// <param name="commit">The git commit SHA, or an empty string.</param>
/// <param name="entropy">The Shannon entropy of the secret.</param>
/// <param name="author">The git author, or an empty string.</param>
/// <param name="email">The git author email, or an empty string.</param>
/// <param name="date">The git commit date, or an empty string.</param>
/// <param name="message">The git commit message, or an empty string.</param>
/// <param name="tags">The rule tags.</param>
/// <param name="fingerprint">The Gitleaks-compatible fingerprint.</param>
/// <param name="line">The full source line that contains the match.</param>
/// <param name="link">The source control link, or an empty string.</param>
/// <param name="secretSha256">The original secret SHA-256 hash for native reports, or an empty string.</param>
/// <param name="matchSha256">The original match SHA-256 hash for native reports, or an empty string.</param>
/// <param name="validationState">The offline validation state for native reports, or an empty string.</param>
public sealed class Finding(
    string ruleID,
    string description,
    int startLine,
    int endLine,
    int startColumn,
    int endColumn,
    string match,
    string secret,
    string file,
    string symlinkFile,
    string commit,
    double entropy,
    string author,
    string email,
    string date,
    string message,
    IReadOnlyList<string> tags,
    string fingerprint,
    string line = "",
    string link = "",
    string secretSha256 = "",
    string matchSha256 = "",
    string validationState = "")
{
    /// <summary>
    /// Gets the rule identifier.
    /// </summary>
    public string RuleID { get; } = ruleID;

    /// <summary>
    /// Gets the rule description.
    /// </summary>
    public string Description { get; } = description;

    /// <summary>
    /// Gets the one-based start line.
    /// </summary>
    public int StartLine { get; } = startLine;

    /// <summary>
    /// Gets the one-based end line.
    /// </summary>
    public int EndLine { get; } = endLine;

    /// <summary>
    /// Gets the one-based start column.
    /// </summary>
    public int StartColumn { get; } = startColumn;

    /// <summary>
    /// Gets the one-based end column.
    /// </summary>
    public int EndColumn { get; } = endColumn;

    /// <summary>
    /// Gets the full source line that contains the match.
    /// </summary>
    public string Line { get; } = line.Length == 0 ? match : line;

    /// <summary>
    /// Gets the full matched text.
    /// </summary>
    public string Match { get; } = match;

    /// <summary>
    /// Gets the secret text.
    /// </summary>
    public string Secret { get; } = secret;

    /// <summary>
    /// Gets the logical file path.
    /// </summary>
    public string File { get; } = file;

    /// <summary>
    /// Gets the symlink path, or an empty string.
    /// </summary>
    public string SymlinkFile { get; } = symlinkFile;

    /// <summary>
    /// Gets the git commit SHA, or an empty string.
    /// </summary>
    public string Commit { get; } = commit;

    /// <summary>
    /// Gets the Shannon entropy of the secret.
    /// </summary>
    public double Entropy { get; } = entropy;

    /// <summary>
    /// Gets the git author, or an empty string.
    /// </summary>
    public string Author { get; } = author;

    /// <summary>
    /// Gets the git author email, or an empty string.
    /// </summary>
    public string Email { get; } = email;

    /// <summary>
    /// Gets the git commit date, or an empty string.
    /// </summary>
    public string Date { get; } = date;

    /// <summary>
    /// Gets the git commit message, or an empty string.
    /// </summary>
    public string Message { get; } = message;

    /// <summary>
    /// Gets the rule tags.
    /// </summary>
    public IReadOnlyList<string> Tags { get; } = tags;

    /// <summary>
    /// Gets the Gitleaks-compatible fingerprint.
    /// </summary>
    public string Fingerprint { get; } = fingerprint;

    /// <summary>
    /// Gets the source control link, or an empty string.
    /// </summary>
    public string Link { get; } = link;

    /// <summary>
    /// Gets the original secret SHA-256 hash for native reports, or an empty string.
    /// </summary>
    public string SecretSha256 { get; } = secretSha256;

    /// <summary>
    /// Gets the original match SHA-256 hash for native reports, or an empty string.
    /// </summary>
    public string MatchSha256 { get; } = matchSha256;

    /// <summary>
    /// Gets the offline validation state for native reports, or an empty string.
    /// </summary>
    public string ValidationState { get; } = validationState;
}
