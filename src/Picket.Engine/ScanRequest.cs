using Picket.Rules;

namespace Picket.Engine;

/// <summary>
/// Describes a byte-buffer scan request.
/// </summary>
/// <param name="input">The input bytes to scan.</param>
/// <param name="fileName">The logical file name used in reports and fingerprints.</param>
/// <param name="ruleSet">The compiled rules used for detection.</param>
public sealed class ScanRequest(ReadOnlyMemory<byte> input, string fileName, CompiledRuleSet ruleSet)
{
    /// <summary>
    /// Initializes a new scan request and compiles the supplied source rules.
    /// </summary>
    /// <param name="input">The input bytes to scan.</param>
    /// <param name="fileName">The logical file name used in reports and fingerprints.</param>
    /// <param name="ruleSet">The source rules used for detection.</param>
    public ScanRequest(ReadOnlyMemory<byte> input, string fileName, RuleSet ruleSet)
        : this(input, fileName, CompiledRuleSet.Compile(ruleSet))
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

    private static string RequireFileName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }
}
