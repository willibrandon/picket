using Picket.Rules;
using System.Security.Cryptography;

namespace Picket.Engine;

/// <summary>
/// Describes a byte-buffer scan request.
/// </summary>
/// <param name="input">The input bytes to scan.</param>
/// <param name="fileName">The logical file name used in reports and fingerprints, or an empty string for stdin compatibility.</param>
/// <param name="ruleSet">The compiled rules used for detection.</param>
/// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.</param>
/// <param name="commit">The git commit SHA used for commit allowlists and fingerprints, or an empty string.</param>
/// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
/// <param name="maxTargetBytes">The maximum content size to scan with content rules, or <see langword="null" /> for no cap.</param>
/// <param name="symlinkFile">The symlink path used in reports, or an empty string.</param>
/// <param name="enableCSharpStringConcatenation">A value indicating whether native scans evaluate deterministic C# string-literal concatenations as derived input.</param>
/// <param name="useGitleaksMaxTargetSemantics">A value indicating whether the target-size limit uses Gitleaks' integer decimal-megabyte comparison.</param>
/// <param name="isCancellationRequested">An optional predicate that stops scanning when it returns <see langword="true" />.</param>
/// <param name="cancellationToken">A cancellation token that stops scanning when cancellation is requested.</param>
public sealed class ScanRequest(
    ReadOnlyMemory<byte> input,
    string fileName,
    CompiledRuleSet ruleSet,
    bool ignoreGitleaksAllow = false,
    string commit = "",
    int maxDecodeDepth = 5,
    long? maxTargetBytes = null,
    string symlinkFile = "",
    bool enableCSharpStringConcatenation = false,
    bool useGitleaksMaxTargetSemantics = false,
    Func<bool>? isCancellationRequested = null,
    CancellationToken cancellationToken = default)
{
    private string _blobSha256 = string.Empty;
    private int _sourceStartColumn = 1;
    private int _sourceStartLine = 1;

    /// <summary>
    /// Initializes a new scan request and compiles the supplied source rules.
    /// </summary>
    /// <param name="input">The input bytes to scan.</param>
    /// <param name="fileName">The logical file name used in reports and fingerprints, or an empty string for stdin compatibility.</param>
    /// <param name="ruleSet">The source rules used for detection.</param>
    /// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> suppression comments are ignored.</param>
    /// <param name="commit">The git commit SHA used for commit allowlists and fingerprints, or an empty string.</param>
    /// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
    /// <param name="maxTargetBytes">The maximum content size to scan with content rules, or <see langword="null" /> for no cap.</param>
    /// <param name="symlinkFile">The symlink path used in reports, or an empty string.</param>
    /// <param name="enableCSharpStringConcatenation">A value indicating whether native scans evaluate deterministic C# string-literal concatenations as derived input.</param>
    /// <param name="useGitleaksMaxTargetSemantics">A value indicating whether the target-size limit uses Gitleaks' integer decimal-megabyte comparison.</param>
    /// <param name="isCancellationRequested">An optional predicate that stops scanning when it returns <see langword="true" />.</param>
    /// <param name="cancellationToken">A cancellation token that stops scanning when cancellation is requested.</param>
    public ScanRequest(
        ReadOnlyMemory<byte> input,
        string fileName,
        RuleSet ruleSet,
        bool ignoreGitleaksAllow = false,
        string commit = "",
        int maxDecodeDepth = 5,
        long? maxTargetBytes = null,
        string symlinkFile = "",
        bool enableCSharpStringConcatenation = false,
        bool useGitleaksMaxTargetSemantics = false,
        Func<bool>? isCancellationRequested = null,
        CancellationToken cancellationToken = default)
        : this(input, fileName, CompiledRuleSet.Compile(ruleSet), ignoreGitleaksAllow, commit, maxDecodeDepth, maxTargetBytes, symlinkFile, enableCSharpStringConcatenation, useGitleaksMaxTargetSemantics, isCancellationRequested, cancellationToken)
    {
    }

    /// <summary>
    /// Gets the input bytes to scan.
    /// </summary>
    public ReadOnlyMemory<byte> Input { get; } = input;

    /// <summary>
    /// Gets the logical file name used in reports and fingerprints, or an empty string for stdin compatibility.
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

    /// <summary>
    /// Gets a value indicating whether native scans evaluate deterministic C# string-literal concatenations as derived input.
    /// </summary>
    public bool EnableCSharpStringConcatenation { get; } = enableCSharpStringConcatenation;

    /// <summary>
    /// Gets a value indicating whether the target-size limit uses Gitleaks' integer decimal-megabyte comparison.
    /// </summary>
    public bool UseGitleaksMaxTargetSemantics { get; } = useGitleaksMaxTargetSemantics;

    /// <summary>
    /// Gets a value indicating whether native scans calculate and apply deterministic randomness scores.
    /// </summary>
    public bool EnableRandomnessScoring { get; init; }

    /// <summary>
    /// Gets a value indicating whether rules may execute built-in native structured detectors.
    /// </summary>
    public bool EnableNativeDetectors { get; init; }

    /// <summary>
    /// Gets the coordinate system used by findings produced by this request.
    /// </summary>
    public FindingPositionKind PositionKind { get; init; }

    /// <summary>
    /// Gets the one-based source line represented by the first input byte.
    /// </summary>
    public int SourceStartLine
    {
        get => _sourceStartLine;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _sourceStartLine = value;
        }
    }

    /// <summary>
    /// Gets the one-based source column represented by the first input byte.
    /// </summary>
    public int SourceStartColumn
    {
        get => _sourceStartColumn;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _sourceStartColumn = value;
        }
    }

    /// <summary>
    /// Gets a precomputed SHA-256 identity for the complete source blob, or an empty string to hash the request input.
    /// </summary>
    public string BlobSha256
    {
        get => _blobSha256;
        init => _blobSha256 = RequireOptionalSha256(value);
    }

    /// <summary>
    /// Gets an optional predicate that stops scanning when it returns <see langword="true" />.
    /// </summary>
    public Func<bool>? IsCancellationRequested { get; } = isCancellationRequested;

    /// <summary>
    /// Gets the cancellation token that stops scanning when cancellation is requested.
    /// </summary>
    public CancellationToken CancellationToken { get; } = cancellationToken;

    private static string RequireFileName(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value;
    }

    private static int RequireNonNegative(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return value;
    }

    private static string RequireOptionalSha256(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
        {
            return string.Empty;
        }

        if (value.Length != SHA256.HashSizeInBytes * 2)
        {
            throw new ArgumentException("The value must be empty or a 64-character SHA-256 hexadecimal hash.", nameof(value));
        }

        for (int i = 0; i < value.Length; i++)
        {
            if (!char.IsAsciiHexDigit(value[i]))
            {
                throw new ArgumentException("The value must be empty or a 64-character SHA-256 hexadecimal hash.", nameof(value));
            }
        }

        return value.ToLowerInvariant();
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
