using Picket.Rules;

namespace Picket.Engine;

/// <summary>
/// Describes a byte-buffer scan request.
/// </summary>
/// <param name="input">The input bytes to scan.</param>
/// <param name="fileName">The logical file name used in reports and fingerprints.</param>
/// <param name="ruleSet">The rules used for detection.</param>
public sealed class ScanRequest(ReadOnlyMemory<byte> input, string fileName, RuleSet ruleSet)
{
    /// <summary>
    /// Gets the input bytes to scan.
    /// </summary>
    public ReadOnlyMemory<byte> Input { get; } = input;

    /// <summary>
    /// Gets the logical file name used in reports and fingerprints.
    /// </summary>
    public string FileName { get; } = RequireFileName(fileName);

    /// <summary>
    /// Gets the rules used for detection.
    /// </summary>
    public RuleSet RuleSet { get; } = ruleSet ?? throw new ArgumentNullException(nameof(ruleSet));

    private static string RequireFileName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }
}
