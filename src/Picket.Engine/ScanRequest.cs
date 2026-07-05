using Picket.Rules;

namespace Picket.Engine;

/// <summary>
/// Describes a byte-buffer scan request.
/// </summary>
/// <param name="input">The input bytes to scan.</param>
/// <param name="fileName">The logical file name used in reports and fingerprints.</param>
/// <param name="ruleSet">The compiled rules used for detection.</param>
/// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.</param>
/// <param name="commit">The git commit SHA used for commit allowlists and fingerprints, or an empty string.</param>
/// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
/// <param name="maxTargetBytes">The maximum content size to scan with content rules, or <see langword="null" /> for no cap.</param>
/// <param name="symlinkFile">The symlink path used in reports, or an empty string.</param>
public sealed class ScanRequest(
    ReadOnlyMemory<byte> input,
    string fileName,
    CompiledRuleSet ruleSet,
    bool ignoreGitleaksAllow = false,
    string commit = "",
    int maxDecodeDepth = 5,
    long? maxTargetBytes = null,
    string symlinkFile = "")
{
    /// <summary>
    /// Initializes a new scan request and compiles the supplied source rules.
    /// </summary>
    /// <param name="input">The input bytes to scan.</param>
    /// <param name="fileName">The logical file name used in reports and fingerprints.</param>
    /// <param name="ruleSet">The source rules used for detection.</param>
    /// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.</param>
    /// <param name="commit">The git commit SHA used for commit allowlists and fingerprints, or an empty string.</param>
    /// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
    /// <param name="maxTargetBytes">The maximum content size to scan with content rules, or <see langword="null" /> for no cap.</param>
    /// <param name="symlinkFile">The symlink path used in reports, or an empty string.</param>
    public ScanRequest(
        ReadOnlyMemory<byte> input,
        string fileName,
        RuleSet ruleSet,
        bool ignoreGitleaksAllow = false,
        string commit = "",
        int maxDecodeDepth = 5,
        long? maxTargetBytes = null,
        string symlinkFile = "")
        : this(input, fileName, CompiledRuleSet.Compile(ruleSet), ignoreGitleaksAllow, commit, maxDecodeDepth, maxTargetBytes, symlinkFile)
    {
    }

    /// <summary>
    /// Gets the input bytes to scan.
    /// </summary>
    public ReadOnlyMemory<byte> Input { get; } = input;

    /// <summary>
    /// Gets the logical file name used in reports and fingerprints.
    /// </summary>
    public string FileName { get; } = RequireFileName(fileName);

    /// <summary>
    /// Gets the compiled rules used for detection.
    /// </summary>
    public CompiledRuleSet RuleSet { get; } = ruleSet ?? throw new ArgumentNullException(nameof(ruleSet));

    /// <summary>
    /// Gets a value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.
    /// </summary>
    public bool IgnoreGitleaksAllow { get; } = ignoreGitleaksAllow;

    /// <summary>
    /// Gets the git commit SHA used for commit allowlists and fingerprints, or an empty string.
    /// </summary>
    public string Commit { get; } = commit ?? string.Empty;

    /// <summary>
    /// Gets the maximum recursive decode depth.
    /// </summary>
    public int MaxDecodeDepth { get; } = RequireNonNegative(maxDecodeDepth);

    /// <summary>
    /// Gets the maximum content size to scan with content rules, or <see langword="null" /> for no cap.
    /// </summary>
    public long? MaxTargetBytes { get; } = RequireNonNegative(maxTargetBytes);

    /// <summary>
    /// Gets the symlink path used in reports, or an empty string.
    /// </summary>
    public string SymlinkFile { get; } = symlinkFile ?? string.Empty;

    private static string RequireFileName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    private static int RequireNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static long? RequireNonNegative(long? value)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value.Value);
        }

        return value;
    }
}
