using System.Text;

namespace Picket.Store;

/// <summary>
/// Identifies the scanner configuration and immutable source manifest for a resumable native scan.
/// </summary>
/// <param name="scanFingerprint">The SHA-256 fingerprint for matching behavior.</param>
/// <param name="sourceManifestFingerprint">The SHA-256 fingerprint for the ordered source manifest.</param>
public sealed class RemoteScanCheckpointKey(string scanFingerprint, string sourceManifestFingerprint)
{
    private const int Sha256HexLength = 64;

    /// <summary>
    /// Gets the matching-behavior fingerprint.
    /// </summary>
    public string ScanFingerprint { get; } = RequireFingerprint(scanFingerprint, nameof(scanFingerprint));

    /// <summary>
    /// Gets the ordered source-manifest fingerprint.
    /// </summary>
    public string SourceManifestFingerprint { get; } = RequireFingerprint(sourceManifestFingerprint, nameof(sourceManifestFingerprint));

    /// <summary>
    /// Gets the combined checkpoint identity.
    /// </summary>
    public string Fingerprint => BlobHasher.ComputeSha256Hex(CreateFingerprintMaterial());

    private string CreateFingerprintMaterial()
    {
        var builder = new StringBuilder();
        builder.Append("picket.remote-scan-checkpoint-key.v1\nscan:");
        builder.Append(ScanFingerprint);
        builder.Append("\nmanifest:");
        builder.Append(SourceManifestFingerprint);
        return builder.ToString();
    }

    private static string RequireFingerprint(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != Sha256HexLength)
        {
            throw new ArgumentException("Fingerprint must be a 64-character lowercase SHA-256 hex value.", parameterName);
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (ch is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                throw new ArgumentException("Fingerprint must be a 64-character lowercase SHA-256 hex value.", parameterName);
            }
        }

        return value;
    }
}
