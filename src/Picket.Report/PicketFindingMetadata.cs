using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Report;

internal static class PicketFindingMetadata
{
    internal const string BaselineStatus = "new";
    internal const string Confidence = "high";
    internal const string IgnoreReason = "";
    internal const string ValidationState = "unknown";

    private const string DefaultConfidence = "high";
    private const string DefaultSeverity = "critical";
    private const string LowerHex = "0123456789abcdef";

    internal static Dictionary<string, SecretRule> CreateRuleIndex(IReadOnlyList<SecretRule> rules)
    {
        var ruleIndex = new Dictionary<string, SecretRule>(rules.Count, StringComparer.Ordinal);
        for (int i = 0; i < rules.Count; i++)
        {
            SecretRule rule = rules[i];
            ruleIndex.TryAdd(rule.Id, rule);
        }

        return ruleIndex;
    }

    internal static SecretRule? FindRule(IReadOnlyDictionary<string, SecretRule> ruleIndex, Finding finding)
    {
        return ruleIndex.TryGetValue(finding.RuleID, out SecretRule? rule) ? rule : null;
    }

    internal static string CreateSeverity(SecretRule? rule)
    {
        return rule is null || rule.Severity.Length == 0 ? DefaultSeverity : rule.Severity;
    }

    internal static string CreateConfidence(SecretRule? rule)
    {
        return rule is null || rule.Confidence.Length == 0 ? DefaultConfidence : rule.Confidence;
    }

    internal static string CreateRulePack(SecretRule? rule)
    {
        return rule?.RulePack ?? string.Empty;
    }

    internal static string CreateProvider(SecretRule? rule)
    {
        return rule?.Provider ?? string.Empty;
    }

    internal static string CreateDocumentationUrl(SecretRule? rule)
    {
        return rule?.DocumentationUrl ?? string.Empty;
    }

    internal static IReadOnlyList<string> CreateRemediationLinks(SecretRule? rule)
    {
        return rule is not null && rule.DocumentationUrl.Length != 0 ? [rule.DocumentationUrl] : [];
    }

    internal static string CreateSecuritySeverity(SecretRule? rule)
    {
        string severity = CreateSeverity(rule);
        return severity.ToLowerInvariant() switch
        {
            "critical" => "8.0",
            "high" => "7.0",
            "medium" => "5.0",
            "low" => "3.0",
            "info" or "informational" => "1.0",
            _ => "8.0",
        };
    }

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

    internal static List<string> CreateDecodePath(Finding finding)
    {
        return finding.DecodePath is List<string> decodePath ? decodePath : [.. finding.DecodePath];
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
        return StableFindingFingerprint.Create(finding);
    }

    internal static string FormatRandomnessNumber(double value)
    {
        return double.IsFinite(value) ? value.ToString("0.######", CultureInfo.InvariantCulture) : "0";
    }

    internal static string FormatProbability(double value)
    {
        return double.IsFinite(value) ? value.ToString("R", CultureInfo.InvariantCulture) : "0";
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
