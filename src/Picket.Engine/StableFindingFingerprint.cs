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
    private const string LegacyOpenAiApiKeyRuleId = "picket-openai-api-key";

    /// <summary>
    /// Creates a versioned stable fingerprint for a finding.
    /// </summary>
    /// <param name="finding">The finding to fingerprint.</param>
    /// <returns>The stable Picket-native finding fingerprint.</returns>
    public static string Create(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (IsValid(finding.NativeFingerprint))
        {
            return finding.NativeFingerprint;
        }

        string locationPath = finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
        return CreateCore(finding, locationPath);
    }

    internal static string Create(Finding finding, string locationPath)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentException.ThrowIfNullOrWhiteSpace(locationPath);
        return CreateCore(finding, locationPath);
    }

    private static string CreateCore(Finding finding, string locationPath)
    {
        string normalizedLocationPath = NormalizeLocationPath(locationPath);
        string secretHash = CreateSecretOrMatchHash(finding);
        string decodePath = string.Join('\0', finding.DecodePath);
        string ruleId = GetFingerprintRuleId(finding.RuleID);
        string material = string.Concat(
            Version,
            "\0",
            normalizedLocationPath,
            "\0",
            ruleId,
            "\0",
            secretHash,
            "\0",
            decodePath);

        return string.Concat(Prefix, CreateSha256(material));
    }

    private static string GetFingerprintRuleId(string ruleId)
    {
        return ruleId is "picket-openai-admin-api-key"
            or "picket-openai-legacy-api-key"
            or "picket-openai-project-api-key"
            or "picket-openai-service-account-api-key"
            ? LegacyOpenAiApiKeyRuleId
            : ruleId;
    }

    private static bool IsValid(string fingerprint)
    {
        if (fingerprint.Length != Prefix.Length + 64
            || !fingerprint.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        foreach (char value in fingerprint.AsSpan(Prefix.Length))
        {
            if (!char.IsAsciiHexDigit(value))
            {
                return false;
            }
        }

        return true;
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
