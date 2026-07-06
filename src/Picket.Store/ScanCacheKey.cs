using System.Globalization;

namespace Picket.Store;

/// <summary>
/// Identifies a scanner configuration for persistent scan-cache entries.
/// </summary>
/// <param name="fingerprint">The stable scanner configuration fingerprint.</param>
public sealed class ScanCacheKey(string fingerprint)
{
    private const int Sha256HexLength = 64;

    /// <summary>
    /// Gets the stable scanner configuration fingerprint.
    /// </summary>
    public string Fingerprint { get; } = RequireFingerprint(fingerprint);

    /// <summary>
    /// Creates a scan cache key from rule and scan-option fingerprints.
    /// </summary>
    /// <param name="ruleSetFingerprint">The compiled rule-set fingerprint.</param>
    /// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
    /// <param name="maxTargetBytes">The maximum content size for content rules, or <see langword="null" /> for no cap.</param>
    /// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> comments are ignored.</param>
    /// <returns>The created cache key.</returns>
    public static ScanCacheKey Create(string ruleSetFingerprint, int maxDecodeDepth, long? maxTargetBytes, bool ignoreGitleaksAllow = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleSetFingerprint);
        ArgumentOutOfRangeException.ThrowIfNegative(maxDecodeDepth);
        if (maxTargetBytes.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(maxTargetBytes.Value);
        }

        string material = string.Concat(
            "picket.scan-cache-key.v1\nrules:",
            ruleSetFingerprint,
            "\ndecode:",
            maxDecodeDepth.ToString(CultureInfo.InvariantCulture),
            "\ntarget:",
            maxTargetBytes.HasValue ? maxTargetBytes.Value.ToString(CultureInfo.InvariantCulture) : "none",
            "\nignore-gitleaks-allow:",
            ignoreGitleaksAllow ? "true" : "false");
        return new ScanCacheKey(BlobHasher.ComputeSha256Hex(material));
    }

    private static string RequireFingerprint(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!IsSha256Hex(value))
        {
            throw new ArgumentException("Fingerprint must be a 64-character lowercase SHA-256 hex value.", nameof(value));
        }

        return value;
    }

    private static bool IsSha256Hex(ReadOnlySpan<char> value)
    {
        if (value.Length != Sha256HexLength)
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (ch is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }
}
