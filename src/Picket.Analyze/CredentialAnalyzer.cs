using System.Security.Cryptography;
using System.Text;
using Picket.Engine;

namespace Picket.Analyze;

/// <summary>
/// Produces offline incident-response analysis for detected credentials.
/// </summary>
public static class CredentialAnalyzer
{
    private const string Schema = "picket.analysis.v1";
    private const string OfflineIdentity = "unknown-offline";
    private const string LowerHex = "0123456789abcdef";

    /// <summary>
    /// Analyzes findings without contacting external providers.
    /// </summary>
    /// <param name="findings">The findings to analyze.</param>
    /// <returns>Offline credential analysis records in finding order.</returns>
    public static List<CredentialAnalysis> Analyze(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var analyses = new List<CredentialAnalysis>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            analyses.Add(Analyze(findings[i]));
        }

        return analyses;
    }

    /// <summary>
    /// Analyzes one finding without contacting external providers.
    /// </summary>
    /// <param name="finding">The finding to analyze.</param>
    /// <returns>The offline credential analysis record.</returns>
    public static CredentialAnalysis Analyze(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string validationState = finding.ValidationState.Length == 0 ? "unknown" : finding.ValidationState;
        string provider = InferProvider(finding.RuleID);
        string credentialType = InferCredentialType(finding.RuleID, provider);
        string risk = GetRisk(validationState);
        string secretSha256 = finding.SecretSha256.Length == 0 ? ComputeSha256(finding.Secret) : finding.SecretSha256;
        return new CredentialAnalysis(
            Schema,
            finding.RuleID,
            provider,
            credentialType,
            finding.File,
            finding.StartLine,
            finding.StartColumn,
            finding.Fingerprint,
            secretSha256,
            validationState,
            risk,
            OfflineIdentity,
            ["unknown-offline"],
            ["unknown-offline"],
            CreateRiskSummary(provider, credentialType, validationState),
            CreateRecommendedActions(provider, credentialType, validationState),
            CreateEvidence(finding, validationState, secretSha256));
    }

    private static string InferProvider(string ruleId)
    {
        if (ruleId.StartsWith("github-", StringComparison.Ordinal))
        {
            return "GitHub";
        }

        return ruleId switch
        {
            "aws-access-token" => "AWS",
            "private-key" => "Generic",
            _ => "Unknown",
        };
    }

    private static string InferCredentialType(string ruleId, string provider)
    {
        if (provider.Equals("GitHub", StringComparison.Ordinal))
        {
            return "GitHub token";
        }

        return ruleId switch
        {
            "aws-access-token" => "AWS access key ID",
            "private-key" => "Private key",
            _ => "Secret",
        };
    }

    private static string GetRisk(string validationState)
    {
        return validationState switch
        {
            "structurally-valid" => "critical",
            "unknown" => "high",
            "invalid" => "low",
            "test-credential" => "low",
            _ => "high",
        };
    }

    private static string CreateRiskSummary(string provider, string credentialType, string validationState)
    {
        return validationState switch
        {
            "structurally-valid" => $"{credentialType} matched {provider} offline structure. Live identity, scope, and resource discovery was not performed.",
            "invalid" => $"{credentialType} matched a known rule but failed offline structure checks. Confirm whether the rule or fixture should be refined.",
            "test-credential" => $"{credentialType} appears to be a test, dummy, placeholder, or sample credential.",
            _ => $"{credentialType} requires triage. Offline analysis could not prove provider validity or active access.",
        };
    }

    private static IReadOnlyList<string> CreateRecommendedActions(string provider, string credentialType, string validationState)
    {
        if (validationState.Equals("invalid", StringComparison.Ordinal))
        {
            return [
                "Review the finding and rule to decide whether this is a false positive.",
                "Add a precise allowlist only when the value is confirmed non-sensitive."
            ];
        }

        if (validationState.Equals("test-credential", StringComparison.Ordinal))
        {
            return [
                "Confirm the value is a non-production test credential.",
                "Replace realistic-looking fixtures with clearly invalid placeholders where possible."
            ];
        }

        return provider switch
        {
            "GitHub" => [
                "Rotate or revoke the GitHub token in the owning account or application.",
                "Review token scopes, repository access, and recent audit events.",
                "Search commit history, issues, logs, artifacts, and package metadata for the same credential hash."
            ],
            "AWS" => [
                "Identify the paired AWS secret access key before live validation or revocation.",
                "Disable or rotate the access key in IAM when ownership is confirmed.",
                "Review CloudTrail and IAM last-used data for suspicious activity."
            ],
            _ => [
                $"Rotate or revoke the {credentialType} with the owning provider or system.",
                "Search history, build logs, artifacts, and deployment metadata for reuse.",
                "Add targeted tests or allowlists only after confirming the value is non-sensitive."
            ],
        };
    }

    private static IReadOnlyList<string> CreateEvidence(Finding finding, string validationState, string secretSha256)
    {
        var evidence = new List<string>
        {
            $"location={finding.File}:{finding.StartLine}:{finding.StartColumn}",
            $"validationState={validationState}",
        };

        if (finding.Fingerprint.Length != 0)
        {
            evidence.Add($"fingerprint={finding.Fingerprint}");
        }

        if (secretSha256.Length != 0)
        {
            evidence.Add($"secretSha256={secretSha256}");
        }

        return evidence;
    }

    private static string ComputeSha256(string value)
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
