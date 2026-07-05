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
public sealed class ScanRequest(
    ReadOnlyMemory<byte> input,
    string fileName,
    CompiledRuleSet ruleSet,
    bool ignoreGitleaksAllow = false,
    string commit = "")
{
    /// <summary>
    /// Initializes a new scan request and compiles the supplied source rules.
    /// </summary>
    /// <param name="input">The input bytes to scan.</param>
    /// <param name="fileName">The logical file name used in reports and fingerprints.</param>
    /// <param name="ruleSet">The source rules used for detection.</param>
    /// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.</param>
    /// <param name="commit">The git commit SHA used for commit allowlists and fingerprints, or an empty string.</param>
    public ScanRequest(ReadOnlyMemory<byte> input, string fileName, RuleSet ruleSet, bool ignoreGitleaksAllow = false, string commit = "")
        : this(input, fileName, CompiledRuleSet.Compile(ruleSet), ignoreGitleaksAllow, commit)
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

    private static string RequireFileName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }
}
