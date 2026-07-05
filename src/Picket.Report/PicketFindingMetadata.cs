using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Picket.Engine;

namespace Picket.Report;

internal static class PicketFindingMetadata
{
    internal const string BaselineStatus = "new";
    internal const string Confidence = "high";
    internal const string IgnoreReason = "";
    internal const string Severity = "critical";
    internal const string ValidationState = "unknown";

    private const string LowerHex = "0123456789abcdef";

    internal static string CreateSecretSha256(Finding finding)
    {
        return finding.SecretSha256.Length == 0 ? CreateSha256(finding.Secret) : finding.SecretSha256;
    }

    internal static string CreateMatchSha256(Finding finding)
    {
        return finding.MatchSha256.Length == 0 ? CreateSha256(finding.Match) : finding.MatchSha256;
    }

    internal static string CreateBlobSha256(Finding finding)
    {
        return finding.BlobSha256;
    }

    internal static IReadOnlyList<string> CreateDecodePath(Finding finding)
    {
        return finding.DecodePath;
    }

    internal static string CreateValidationState(Finding finding)
    {
        return finding.ValidationState.Length == 0 ? ValidationState : finding.ValidationState;
    }

    internal static string CreateSha256(string value)
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

    internal static string CreateFingerprint(Finding finding)
    {
        return finding.Fingerprint.Length == 0
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"{CreateLocationPath(finding)}:{finding.RuleID}:{finding.StartLine}:{finding.StartColumn}")
            : finding.Fingerprint;
    }

    internal static string CreateLocationPath(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    internal static string CreateProvenanceType(Finding finding)
    {
        return finding.Commit.Length == 0 ? "filesystem" : "git";
    }
}
