using System.Security.Cryptography;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Creates stable Picket-native finding fingerprints.
/// </summary>
public static class StableFindingFingerprint
{
    private const string Prefix = "picket:v1:";
    private const string Version = "picket.finding.fingerprint.v1";
    private const string LowerHex = "0123456789abcdef";

    /// <summary>
    /// Creates a versioned stable fingerprint for a finding.
    /// </summary>
    /// <param name="finding">The finding to fingerprint.</param>
    /// <returns>The stable Picket-native finding fingerprint.</returns>
    public static string Create(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string locationPath = NormalizeLocationPath(finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile);
        string secretHash = CreateSecretOrMatchHash(finding);
        string decodePath = string.Join('\0', finding.DecodePath);
        string material = string.Concat(
            Version,
            "\0",
            locationPath,
            "\0",
            finding.RuleID,
            "\0",
            secretHash,
            "\0",
            decodePath);

        return string.Concat(Prefix, CreateSha256(material));
    }

    private static string CreateSecretOrMatchHash(Finding finding)
    {
        if (finding.SecretSha256.Length != 0)
        {
            return finding.SecretSha256.ToLowerInvariant();
        }

        if (finding.Secret.Length != 0)
        {
            return CreateSha256(finding.Secret);
        }

        if (finding.MatchSha256.Length != 0)
        {
            return finding.MatchSha256.ToLowerInvariant();
        }

        return CreateSha256(finding.Match);
    }

    private static string NormalizeLocationPath(string path)
    {
        return path.Replace('\\', '/');
    }

    private static string CreateSha256(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return string.Create(hash.Length * 2, hash, static (chars, bytes) =>
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte value = bytes[i];
                chars[i * 2] = LowerHex[value >> 4];
                chars[(i * 2) + 1] = LowerHex[value & 0x0F];
            }
        });
    }
}
