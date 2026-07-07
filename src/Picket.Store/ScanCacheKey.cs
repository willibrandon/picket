using System.Globalization;
using System.Text;

namespace Picket.Store;

/// <summary>
/// Identifies a scanner configuration for persistent scan-cache entries.
/// </summary>
/// <param name="fingerprint">The stable scanner configuration fingerprint.</param>
/// <param name="addressMode">The cache address mode used for blob entries.</param>
/// <param name="storageMode">The cache storage mode used for finding evidence.</param>
public sealed class ScanCacheKey(
    string fingerprint,
    ScanCacheAddressMode addressMode = ScanCacheAddressMode.Path,
    ScanCacheStorageMode storageMode = ScanCacheStorageMode.SecretHashOnly)
{
    private const int Sha256HexLength = 64;

    /// <summary>
    /// Gets the stable scanner configuration fingerprint.
    /// </summary>
    public string Fingerprint { get; } = RequireFingerprint(fingerprint);

    /// <summary>
    /// Gets the cache address mode used for blob entries.
    /// </summary>
    public ScanCacheAddressMode AddressMode { get; } = RequireAddressMode(addressMode);

    /// <summary>
    /// Gets the cache storage mode used for finding evidence.
    /// </summary>
    public ScanCacheStorageMode StorageMode { get; } = RequireStorageMode(storageMode);

    /// <summary>
    /// Creates a scan cache key from rule and scan-option fingerprints.
    /// </summary>
    /// <param name="ruleSetFingerprint">The compiled rule-set fingerprint.</param>
    /// <param name="maxDecodeDepth">The maximum recursive decode depth.</param>
    /// <param name="maxTargetBytes">The maximum content size for content rules, or <see langword="null" /> for no cap.</param>
    /// <param name="ignoreGitleaksAllow">A value indicating whether inline <c>gitleaks:allow</c> comments are ignored.</param>
    /// <param name="addressMode">The cache address mode used for blob entries.</param>
    /// <param name="storageMode">The cache storage mode used for finding evidence.</param>
    /// <returns>The created cache key.</returns>
    public static ScanCacheKey Create(
        string ruleSetFingerprint,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool ignoreGitleaksAllow = false,
        ScanCacheAddressMode addressMode = ScanCacheAddressMode.Path,
        ScanCacheStorageMode storageMode = ScanCacheStorageMode.SecretHashOnly)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleSetFingerprint);
        ArgumentOutOfRangeException.ThrowIfNegative(maxDecodeDepth);
        if (maxTargetBytes.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(maxTargetBytes.Value);
        }

        ScanCacheAddressMode normalizedAddressMode = RequireAddressMode(addressMode);
        ScanCacheStorageMode normalizedStorageMode = RequireStorageMode(storageMode);
        string material = CreateFingerprintMaterial(
            ruleSetFingerprint,
            maxDecodeDepth,
            maxTargetBytes,
            ignoreGitleaksAllow,
            normalizedAddressMode,
            normalizedStorageMode);
        return new ScanCacheKey(BlobHasher.ComputeSha256Hex(material), normalizedAddressMode, normalizedStorageMode);
    }

    private static string CreateFingerprintMaterial(
        string ruleSetFingerprint,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool ignoreGitleaksAllow,
        ScanCacheAddressMode addressMode,
        ScanCacheStorageMode storageMode)
    {
        var builder = new StringBuilder();
        builder.Append("picket.scan-cache-key.v1\nrules:");
        builder.Append(ruleSetFingerprint);
        builder.Append("\ndecode:");
        builder.Append(maxDecodeDepth.ToString(CultureInfo.InvariantCulture));
        builder.Append("\ntarget:");
        builder.Append(maxTargetBytes.HasValue ? maxTargetBytes.Value.ToString(CultureInfo.InvariantCulture) : "none");
        builder.Append("\nignore-gitleaks-allow:");
        builder.Append(ignoreGitleaksAllow ? "true" : "false");
        if (addressMode != ScanCacheAddressMode.Path)
        {
            builder.Append("\naddress-mode:");
            builder.Append(addressMode.ToString());
        }

        if (storageMode != ScanCacheStorageMode.Raw)
        {
            builder.Append("\nstorage-mode:");
            builder.Append(storageMode.ToString());
        }

        return builder.ToString();
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

    private static ScanCacheAddressMode RequireAddressMode(ScanCacheAddressMode value)
    {
        return value is ScanCacheAddressMode.Path or ScanCacheAddressMode.FileExtension or ScanCacheAddressMode.Content
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value), value, "Value must be a supported cache address mode.");
    }

    private static ScanCacheStorageMode RequireStorageMode(ScanCacheStorageMode value)
    {
        return value is ScanCacheStorageMode.Raw or ScanCacheStorageMode.SecretHashOnly
            ? value
            : throw new ArgumentOutOfRangeException(nameof(value), value, "Value must be a supported cache storage mode.");
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
