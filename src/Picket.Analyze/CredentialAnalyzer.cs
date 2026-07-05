using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
            StableFindingFingerprint.Create(finding),
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
            "gcp-api-key" => "GCP",
            "picket-gcp-service-account-key" => "GCP",
            "picket-azure-storage-connection-string" => "Azure",
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
            "gcp-api-key" => "GCP API key",
            "picket-gcp-service-account-key" => "GCP service account key",
            "picket-azure-storage-connection-string" => "Azure Storage account key",
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
            "Azure" => [
                "Rotate one Azure Storage account key, update dependent applications, then rotate the second key.",
                "Review storage account diagnostics, access logs, SAS token issuance, and firewall/network rules.",
                "Search application settings, deployment outputs, CI variables, and logs for the same credential hash."
            ],
            "GCP" when credentialType.Equals("GCP API key", StringComparison.Ordinal) => [
                "Rotate the Google API key or delete it after dependent applications are updated.",
                "Review and tighten API key restrictions for allowed APIs, HTTP referrers, IP addresses, Android apps, or iOS apps.",
                "Review Google Cloud API key usage metrics and audit logs for suspicious activity."
            ],
            "GCP" => [
                "Disable or delete the leaked service account key in Google Cloud IAM.",
                "Review the service account IAM roles, key usage, and Cloud Audit Logs for suspicious activity.",
                "Move the workload to a rotated key or keyless authentication such as Workload Identity where possible."
            ],
            _ => [
                $"Rotate or revoke the {credentialType} with the owning provider or system.",
                "Search history, build logs, artifacts, and deployment metadata for reuse.",
                "Add targeted tests or allowlists only after confirming the value is non-sensitive."
            ],
        };
    }

    private static List<string> CreateEvidence(Finding finding, string validationState, string secretSha256)
    {
        var evidence = new List<string>
        {
            $"location={finding.File}:{finding.StartLine}:{finding.StartColumn}",
            $"validationState={validationState}",
        };

        evidence.Add($"fingerprint={StableFindingFingerprint.Create(finding)}");

        if (secretSha256.Length != 0)
        {
            evidence.Add($"secretSha256={secretSha256}");
        }

        if (finding.RuleID.Equals("picket-azure-storage-connection-string", StringComparison.Ordinal)
            && TryGetConnectionStringField(finding.Match, "AccountName", out string accountName))
        {
            evidence.Add($"accountName={accountName}");
        }

        if (finding.RuleID.Equals("picket-gcp-service-account-key", StringComparison.Ordinal)
            && TryReadGcpServiceAccountEvidence(GetFindingSecretMaterial(finding), out string projectId, out string clientEmail))
        {
            evidence.Add($"projectId={projectId}");
            evidence.Add($"clientEmail={clientEmail}");
        }

        return evidence;
    }

    private static string GetFindingSecretMaterial(Finding finding)
    {
        return finding.Secret.Length == 0 ? finding.Match : finding.Secret;
    }

    private static bool TryReadGcpServiceAccountEvidence(string json, out string projectId, out string clientEmail)
    {
        projectId = string.Empty;
        clientEmail = string.Empty;
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !TryGetJsonString(document.RootElement, "project_id", out projectId)
                || !TryGetJsonString(document.RootElement, "client_email", out clientEmail))
            {
                return false;
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryGetJsonString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(propertyName, out JsonElement property)
            || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return value.Length != 0;
    }

    private static bool TryGetConnectionStringField(string connectionString, string fieldName, out string fieldValue)
    {
        ReadOnlySpan<char> remaining = connectionString.AsSpan().Trim();
        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOf(';');
            ReadOnlySpan<char> segment = separator < 0 ? remaining : remaining[..separator];
            segment = segment.Trim();
            if (!segment.IsEmpty)
            {
                int equals = segment.IndexOf('=');
                if (equals <= 0)
                {
                    fieldValue = string.Empty;
                    return false;
                }

                ReadOnlySpan<char> key = segment[..equals].Trim();
                if (key.Equals(fieldName.AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    fieldValue = segment[(equals + 1)..].Trim().ToString();
                    return true;
                }
            }

            if (separator < 0)
            {
                break;
            }

            remaining = remaining[(separator + 1)..];
        }

        fieldValue = string.Empty;
        return false;
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
