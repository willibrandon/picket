using Picket.Engine;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Picket.Analyze;

/// <summary>
/// Produces incident-response analysis for detected credentials.
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
        return Analyze(findings, null);
    }

    /// <summary>
    /// Analyzes findings with optional non-secret provider metadata.
    /// </summary>
    /// <param name="findings">The findings to analyze.</param>
    /// <param name="metadataByFingerprint">The optional provider metadata keyed by stable finding fingerprint.</param>
    /// <returns>Credential analysis records in finding order.</returns>
    public static List<CredentialAnalysis> Analyze(
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, CredentialAnalysisMetadata>? metadataByFingerprint)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var analyses = new List<CredentialAnalysis>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            string fingerprint = StableFindingFingerprint.Create(finding);
            CredentialAnalysisMetadata? metadata = metadataByFingerprint is not null
                && metadataByFingerprint.TryGetValue(fingerprint, out CredentialAnalysisMetadata? value)
                    ? value
                    : null;
            analyses.Add(Analyze(finding, metadata));
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
        return Analyze(finding, metadata: null);
    }

    /// <summary>
    /// Analyzes one finding with optional non-secret provider metadata.
    /// </summary>
    /// <param name="finding">The finding to analyze.</param>
    /// <param name="metadata">The optional provider metadata.</param>
    /// <returns>The credential analysis record.</returns>
    public static CredentialAnalysis Analyze(Finding finding, CredentialAnalysisMetadata? metadata)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string validationState = finding.ValidationState.Length == 0 ? "unknown" : finding.ValidationState;
        string provider = InferProvider(finding.RuleID);
        string credentialType = InferCredentialType(finding.RuleID, provider);
        string risk = GetRisk(validationState);
        string secretSha256 = finding.SecretSha256.Length == 0 ? ComputeSha256(finding.Secret) : finding.SecretSha256;
        string fingerprint = StableFindingFingerprint.Create(finding);
        return new CredentialAnalysis(
            Schema,
            finding.RuleID,
            provider,
            credentialType,
            finding.File,
            finding.StartLine,
            finding.StartColumn,
            fingerprint,
            secretSha256,
            validationState,
            risk,
            CreateIdentity(metadata, validationState),
            CreateMetadataList(metadata?.Scopes, validationState),
            CreateMetadataList(metadata?.ReachableResources, validationState),
            CreateRiskSummary(provider, credentialType, validationState),
            CreateRecommendedActions(provider, credentialType, validationState),
            CreateRevocationAvailable(provider, credentialType),
            CreateRevocationCommands(finding, provider, credentialType),
            CreateRevocationGuidance(provider, credentialType),
            CreateEvidence(finding, validationState, secretSha256, metadata));
    }

    private static string InferProvider(string ruleId)
    {
        if (IsGitHubRuleId(ruleId))
        {
            return "GitHub";
        }

        if (IsGitLabRuleId(ruleId))
        {
            return "GitLab";
        }

        return ruleId switch
        {
            "aws-access-token" => "AWS",
            "picket-aws-access-key-pair" => "AWS",
            "gcp-api-key" => "GCP",
            "picket-google-api-key" => "GCP",
            "picket-gcp-service-account-key" => "GCP",
            "picket-azure-storage-connection-string" => "Azure",
            "picket-database-connection-url" => "Database",
            "picket-sourcegraph-access-token" => "Sourcegraph",
            "private-key" => "Generic",
            _ => "Unknown",
        };
    }

    private static string InferCredentialType(string ruleId, string provider)
    {
        if (ruleId.Equals("picket-github-app-token", StringComparison.Ordinal))
        {
            return "GitHub App token";
        }

        if (ruleId.Equals("picket-github-fine-grained-personal-access-token", StringComparison.Ordinal))
        {
            return "GitHub fine-grained personal access token";
        }

        if (ruleId.Equals("picket-github-oauth-token", StringComparison.Ordinal))
        {
            return "GitHub OAuth token";
        }

        if (ruleId.Equals("picket-github-personal-access-token", StringComparison.Ordinal))
        {
            return "GitHub personal access token";
        }

        if (ruleId.Equals("picket-github-refresh-token", StringComparison.Ordinal))
        {
            return "GitHub refresh token";
        }

        if (provider.Equals("GitHub", StringComparison.Ordinal))
        {
            return "GitHub token";
        }

        if (ruleId.Equals("gitlab-cicd-job-token", StringComparison.Ordinal))
        {
            return "GitLab CI/CD job token";
        }

        if (ruleId.Equals("gitlab-deploy-token", StringComparison.Ordinal))
        {
            return "GitLab deploy token";
        }

        if (ruleId.Equals("gitlab-feature-flag-client-token", StringComparison.Ordinal))
        {
            return "GitLab feature flag client token";
        }

        if (ruleId.Equals("gitlab-feed-token", StringComparison.Ordinal))
        {
            return "GitLab feed token";
        }

        if (ruleId.Equals("gitlab-incoming-mail-token", StringComparison.Ordinal))
        {
            return "GitLab incoming mail token";
        }

        if (ruleId.Equals("gitlab-kubernetes-agent-token", StringComparison.Ordinal))
        {
            return "GitLab Kubernetes agent token";
        }

        if (ruleId.Equals("gitlab-oauth-app-secret", StringComparison.Ordinal))
        {
            return "GitLab OAuth application secret";
        }

        if (ruleId is "gitlab-pat" or "gitlab-pat-routable"
            || ruleId.Equals("picket-gitlab-personal-access-token", StringComparison.Ordinal))
        {
            return "GitLab personal access token";
        }

        if (ruleId.Equals("gitlab-ptt", StringComparison.Ordinal))
        {
            return "GitLab pipeline trigger token";
        }

        if (ruleId.Equals("gitlab-rrt", StringComparison.Ordinal))
        {
            return "GitLab runner registration token";
        }

        if (ruleId is "gitlab-runner-authentication-token" or "gitlab-runner-authentication-token-routable")
        {
            return "GitLab runner authentication token";
        }

        if (ruleId.Equals("gitlab-scim-token", StringComparison.Ordinal))
        {
            return "GitLab SCIM token";
        }

        if (ruleId.Equals("gitlab-session-cookie", StringComparison.Ordinal))
        {
            return "GitLab session cookie";
        }

        if (provider.Equals("GitLab", StringComparison.Ordinal))
        {
            return "GitLab token";
        }

        return ruleId switch
        {
            "aws-access-token" => "AWS access key ID",
            "picket-aws-access-key-pair" => "AWS access key pair",
            "gcp-api-key" => "GCP API key",
            "picket-google-api-key" => "GCP API key",
            "picket-gcp-service-account-key" => "GCP service account key",
            "picket-azure-storage-connection-string" => "Azure Storage account key",
            "picket-database-connection-url" => "Database connection URL",
            "picket-sourcegraph-access-token" => "Sourcegraph access token",
            "private-key" => "Private key",
            _ => "Secret",
        };
    }

    private static bool IsGitHubRuleId(string ruleId)
    {
        return ruleId.StartsWith("github-", StringComparison.Ordinal)
            || ruleId.StartsWith("picket-github-", StringComparison.Ordinal);
    }

    private static bool IsGitLabRuleId(string ruleId)
    {
        return ruleId.StartsWith("gitlab-", StringComparison.Ordinal)
            || ruleId.StartsWith("picket-gitlab-", StringComparison.Ordinal);
    }

    private static string GetRisk(string validationState)
    {
        return validationState switch
        {
            "active" => "critical",
            "structurally-valid" => "critical",
            "inactive" => "medium",
            "unknown" => "high",
            "skipped" => "high",
            "error" => "high",
            "invalid" => "low",
            "test-credential" => "low",
            _ => "high",
        };
    }

    private static string CreateRiskSummary(string provider, string credentialType, string validationState)
    {
        return validationState switch
        {
            "active" => $"{provider} accepted the {credentialType}. Identity, scope, and reachable-resource evidence is included when the provider exposed it.",
            "inactive" => $"{provider} rejected the {credentialType}. Treat it as previously exposed until history, logs, and reuse have been checked.",
            "skipped" => $"{credentialType} was not eligible for live provider analysis with the currently configured validators.",
            "error" => $"{credentialType} could not be analyzed live because provider validation failed or was blocked by policy.",
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
            "GitLab" => [
                "Revoke or rotate the GitLab credential in the owning user, project, group, runner, agent, or application.",
                "Review token scopes, group and project membership, protected branch and tag permissions, package registry access, container registry access, and recent audit events.",
                "Search repositories, CI variables, pipeline logs, job artifacts, releases, packages, issues, and merge requests for the same credential hash."
            ],
            "Database" => [
                "Rotate the database password or connection credential and update every dependent application configuration.",
                "Review database authentication logs, connection history, network allowlists, grants, roles, and recent schema or data access.",
                "Search source history, CI variables, deployment manifests, container images, logs, and artifacts for the same credential hash."
            ],
            "Sourcegraph" => [
                "Generate a replacement Sourcegraph access token with the minimum required permissions, update consumers, then revoke the exposed token.",
                "Review Sourcegraph audit events, API usage, Cody access, batch changes, and code-host permissions for suspicious activity.",
                "Search repositories, CI variables, deployment manifests, logs, and artifacts for the same credential hash."
            ],
            "AWS" => [
                credentialType.Equals("AWS access key pair", StringComparison.Ordinal)
                    ? "Disable or rotate the leaked AWS access key in IAM after dependent workloads are updated."
                    : "Identify the paired AWS secret access key before live validation or revocation.",
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

    private static bool CreateRevocationAvailable(string provider, string credentialType)
    {
        return provider switch
        {
            "AWS" => credentialType.Equals("AWS access key pair", StringComparison.Ordinal),
            "Azure" => credentialType.Equals("Azure Storage account key", StringComparison.Ordinal),
            "GCP" => credentialType is "GCP API key" or "GCP service account key",
            "GitHub" => true,
            "GitLab" => true,
            "Database" => credentialType.Equals("Database connection URL", StringComparison.Ordinal),
            "Sourcegraph" => credentialType.Equals("Sourcegraph access token", StringComparison.Ordinal),
            _ => false,
        };
    }

    private static List<string> CreateRevocationCommands(Finding finding, string provider, string credentialType)
    {
        if (provider.Equals("AWS", StringComparison.Ordinal)
            && credentialType.Equals("AWS access key pair", StringComparison.Ordinal))
        {
            string accessKeyId = TryReadAwsAccessKeyId(finding.Match, out string parsedAccessKeyId)
                ? parsedAccessKeyId
                : "<access-key-id>";
            return [
                $"aws iam get-access-key-last-used --access-key-id {accessKeyId}",
                $"aws iam update-access-key --access-key-id {accessKeyId} --status Inactive --user-name <iam-user>",
                $"aws iam delete-access-key --access-key-id {accessKeyId} --user-name <iam-user>"
            ];
        }

        if (provider.Equals("Azure", StringComparison.Ordinal)
            && credentialType.Equals("Azure Storage account key", StringComparison.Ordinal))
        {
            string accountName = TryGetConnectionStringField(finding.Match, "AccountName", out string parsedAccountName)
                ? parsedAccountName
                : "<storage-account>";
            return [
                $"az storage account keys renew --account-name {accountName} --resource-group <resource-group> --key primary",
                $"az storage account keys renew --account-name {accountName} --resource-group <resource-group> --key secondary"
            ];
        }

        if (provider.Equals("GitHub", StringComparison.Ordinal))
        {
            return [
                "curl -L -X POST -H \"Accept: application/vnd.github+json\" -H \"X-GitHub-Api-Version: 2026-03-10\" https://api.github.com/credentials/revoke -d '{\"credentials\":[\"<github-token>\"]}'"
            ];
        }

        if (provider.Equals("GitLab", StringComparison.Ordinal))
        {
            return CreateGitLabRevocationCommands(credentialType);
        }

        if (provider.Equals("GCP", StringComparison.Ordinal)
            && credentialType.Equals("GCP service account key", StringComparison.Ordinal)
            && TryReadGcpServiceAccountEvidence(
                GetFindingSecretMaterial(finding),
                out _,
                out string clientEmail,
                out string privateKeyId))
        {
            return [
                $"gcloud iam service-accounts keys list --iam-account={clientEmail}",
                $"gcloud iam service-accounts keys delete {privateKeyId} --iam-account={clientEmail}"
            ];
        }

        if (provider.Equals("GCP", StringComparison.Ordinal)
            && credentialType.Equals("GCP API key", StringComparison.Ordinal))
        {
            return [
                "gcloud services api-keys delete <key-id> --project <project-id> --location global"
            ];
        }

        return [];
    }

    private static IReadOnlyList<string> CreateRevocationGuidance(string provider, string credentialType)
    {
        return provider switch
        {
            "GitHub" => [
                "Submit the leaked token to GitHub's credential revocation API or revoke it from the owner's token settings.",
                "For GitHub App tokens, also review the app installation and rotate app credentials or suspend/remove the installation when required.",
                "Re-run analysis after revocation to confirm the provider no longer accepts the credential."
            ],
            "AWS" when credentialType.Equals("AWS access key pair", StringComparison.Ordinal) => [
                "Create or identify the replacement key first when workloads still depend on this IAM principal.",
                "Disable the leaked access key, verify dependent workloads, then delete the key.",
                "Use IAM last-used data and CloudTrail to decide the investigation window."
            ],
            "Azure" when credentialType.Equals("Azure Storage account key", StringComparison.Ordinal) => [
                "Move consumers to the alternate storage account key before regenerating the compromised key.",
                "Regenerate the compromised key, update consumers, then rotate the alternate key.",
                "Review storage diagnostics, SAS issuance, and network controls after rotation."
            ],
            "GCP" when credentialType.Equals("GCP service account key", StringComparison.Ordinal) => [
                "Delete the exposed user-managed service account key after confirming workloads have moved to a replacement.",
                "Prefer service account impersonation or Workload Identity over long-lived JSON keys.",
                "Review IAM roles and Cloud Audit Logs for use of the leaked key."
            ],
            "GCP" when credentialType.Equals("GCP API key", StringComparison.Ordinal) => [
                "Find the API key resource in Google Cloud API Keys before deleting or replacing it.",
                "Create a replacement with required API and application restrictions before updating consumers.",
                "Delete the exposed key after traffic has moved to the replacement."
            ],
            "GitLab" => CreateGitLabRevocationGuidance(credentialType),
            "Database" when credentialType.Equals("Database connection URL", StringComparison.Ordinal) => [
                "Identify the database user and owning application from configuration management before rotation.",
                "Create or assign a replacement credential with the same minimum required privileges, update consumers, then revoke or change the exposed password.",
                "Review database audit logs, role grants, network access rules, backups, and downstream exports for post-exposure access."
            ],
            "Sourcegraph" when credentialType.Equals("Sourcegraph access token", StringComparison.Ordinal) => [
                "Identify the Sourcegraph user or integration that owns the token before revocation.",
                "Create a replacement token with least-privilege permissions, update every consumer, then delete the exposed access token from Sourcegraph token settings.",
                "For self-hosted Sourcegraph, review audit logs, code-host permissions, Cody usage, and batch changes activity during the exposure window."
            ],
            _ => [],
        };
    }

    private static List<string> CreateGitLabRevocationCommands(string credentialType)
    {
        return credentialType switch
        {
            "GitLab personal access token" => [
                "curl --request DELETE --header \"PRIVATE-TOKEN: <gitlab-admin-token>\" \"https://gitlab.example.com/api/v4/personal_access_tokens/<token-id>\""
            ],
            "GitLab deploy token" => [
                "curl --request DELETE --header \"PRIVATE-TOKEN: <gitlab-admin-token>\" \"https://gitlab.example.com/api/v4/projects/<project-id>/deploy_tokens/<deploy-token-id>\"",
                "curl --request DELETE --header \"PRIVATE-TOKEN: <gitlab-admin-token>\" \"https://gitlab.example.com/api/v4/groups/<group-id>/deploy_tokens/<deploy-token-id>\""
            ],
            "GitLab pipeline trigger token" => [
                "curl --request DELETE --header \"PRIVATE-TOKEN: <gitlab-maintainer-token>\" \"https://gitlab.example.com/api/v4/projects/<project-id>/triggers/<trigger-id>\""
            ],
            "GitLab runner authentication token" => [
                "gitlab-runner unregister --url https://gitlab.example.com --token <runner-authentication-token>"
            ],
            _ => [],
        };
    }

    private static IReadOnlyList<string> CreateGitLabRevocationGuidance(string credentialType)
    {
        if (credentialType.Equals("GitLab CI/CD job token", StringComparison.Ordinal))
        {
            return [
                "Cancel the exposing pipeline if it is still running, then review the job token permissions and project allowlist.",
                "Rotate any CI variables, deploy credentials, package tokens, or registry credentials the job could read.",
                "Review job logs and artifacts before retention or cleanup removes investigation evidence."
            ];
        }

        return [
            "Identify the owning GitLab user, project, group, runner, agent, or application before revocation.",
            "Revoke the credential from the narrowest owning surface, then rotate dependent jobs, integrations, runners, and deployments.",
            "Review GitLab audit events, project access tokens, group access tokens, deploy tokens, pipeline triggers, runners, packages, and registry activity for post-exposure use."
        ];
    }

    private static string CreateIdentity(CredentialAnalysisMetadata? metadata, string validationState)
    {
        if (metadata is not null && metadata.Identity.Length != 0)
        {
            return metadata.Identity;
        }

        return IsLiveValidationState(validationState) ? "unknown-live" : OfflineIdentity;
    }

    private static IReadOnlyList<string> CreateMetadataList(IReadOnlyList<string>? values, string validationState)
    {
        if (values is not null && values.Count != 0)
        {
            return values;
        }

        return IsLiveValidationState(validationState) ? ["unknown-live"] : ["unknown-offline"];
    }

    private static bool IsLiveValidationState(string validationState)
    {
        return validationState is "active" or "inactive" or "skipped" or "error";
    }

    private static List<string> CreateEvidence(
        Finding finding,
        string validationState,
        string secretSha256,
        CredentialAnalysisMetadata? metadata)
    {
        var evidence = new List<string>
        {
            $"location={finding.File}:{finding.StartLine}:{finding.StartColumn}",
            $"validationState={validationState}",
            $"fingerprint={StableFindingFingerprint.Create(finding)}"
        };

        if (secretSha256.Length != 0)
        {
            evidence.Add($"secretSha256={secretSha256}");
        }

        if (finding.RuleID.Equals("picket-azure-storage-connection-string", StringComparison.Ordinal)
            && TryGetConnectionStringField(finding.Match, "AccountName", out string accountName))
        {
            evidence.Add($"accountName={accountName}");
        }

        if (finding.RuleID.Equals("picket-aws-access-key-pair", StringComparison.Ordinal)
            && TryReadAwsAccessKeyId(finding.Match, out string accessKeyId))
        {
            evidence.Add($"accessKeyId={accessKeyId}");
            evidence.Add($"resourceType={GetAwsResourceType(accessKeyId)}");
        }

        if (finding.RuleID.Equals("picket-gcp-service-account-key", StringComparison.Ordinal)
            && TryReadGcpServiceAccountEvidence(
                GetFindingSecretMaterial(finding),
                out string projectId,
                out string clientEmail,
                out string privateKeyId))
        {
            evidence.Add($"projectId={projectId}");
            evidence.Add($"clientEmail={clientEmail}");
            evidence.Add($"privateKeyId={privateKeyId}");
        }

        if (finding.RuleID.Equals("picket-database-connection-url", StringComparison.Ordinal)
            && TryReadDatabaseConnectionEvidence(
                GetFindingSecretMaterial(finding),
                out string databaseScheme,
                out string databaseUser))
        {
            evidence.Add($"databaseScheme={databaseScheme}");
            evidence.Add($"databaseUser={databaseUser}");
        }

        if (finding.RuleID.Equals("picket-sourcegraph-access-token", StringComparison.Ordinal)
            && TryReadSourcegraphTokenEvidence(GetFindingSecretMaterial(finding), out string sourcegraphTokenVersion))
        {
            evidence.Add($"sourcegraphTokenVersion={sourcegraphTokenVersion}");
        }

        if (IsGitLabRuleId(finding.RuleID))
        {
            evidence.Add($"gitLabRuleId={finding.RuleID}");
            evidence.Add($"resourceType={GetGitLabResourceType(finding.RuleID)}");
        }

        if (metadata is not null)
        {
            for (int i = 0; i < metadata.Evidence.Count; i++)
            {
                evidence.Add(metadata.Evidence[i]);
            }
        }

        return evidence;
    }

    private static bool TryReadDatabaseConnectionEvidence(string secret, out string scheme, out string user)
    {
        scheme = string.Empty;
        user = string.Empty;
        if (!Uri.TryCreate(secret, UriKind.Absolute, out Uri? uri)
            || uri.Scheme.Length == 0
            || uri.UserInfo.Length == 0)
        {
            return false;
        }

        int separator = uri.UserInfo.IndexOf(':');
        if (separator <= 0)
        {
            return false;
        }

        scheme = uri.Scheme;
        user = uri.UserInfo[..separator];
        return true;
    }

    private static bool TryReadSourcegraphTokenEvidence(string secret, out string tokenVersion)
    {
        tokenVersion = string.Empty;
        const string Prefix = "sgp_";
        if (!secret.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        ReadOnlySpan<char> body = secret.AsSpan(Prefix.Length);
        int separator = body.IndexOf('_');
        if (separator < 0)
        {
            tokenVersion = "v2";
            return body.Length == 40;
        }

        tokenVersion = "v3";
        return body[(separator + 1)..].Length == 40;
    }

    private static string GetGitLabResourceType(string ruleId)
    {
        return ruleId switch
        {
            "gitlab-cicd-job-token" => "ci-job-token",
            "gitlab-deploy-token" => "deploy-token",
            "gitlab-feature-flag-client-token" => "feature-flag-client-token",
            "gitlab-feed-token" => "feed-token",
            "gitlab-incoming-mail-token" => "incoming-mail-token",
            "gitlab-kubernetes-agent-token" => "kubernetes-agent-token",
            "gitlab-oauth-app-secret" => "oauth-application-secret",
            "gitlab-pat" or "gitlab-pat-routable" or "picket-gitlab-personal-access-token" => "personal-access-token",
            "gitlab-ptt" => "pipeline-trigger-token",
            "gitlab-rrt" => "runner-registration-token",
            "gitlab-runner-authentication-token" or "gitlab-runner-authentication-token-routable" => "runner-authentication-token",
            "gitlab-scim-token" => "scim-token",
            "gitlab-session-cookie" => "session-cookie",
            _ => "token",
        };
    }

    private static string GetFindingSecretMaterial(Finding finding)
    {
        return finding.Secret.Length == 0 ? finding.Match : finding.Secret;
    }

    private static bool TryReadAwsAccessKeyId(string value, out string accessKeyId)
    {
        int lastStart = value.Length - 20;
        for (int start = 0; start <= lastStart; start++)
        {
            string candidate = value.Substring(start, 20);
            if (IsAwsAccessKeyId(candidate)
                && (start == 0 || !IsAsciiAlphaNumeric(value[start - 1]))
                && (start + 20 == value.Length || !IsAsciiAlphaNumeric(value[start + 20])))
            {
                accessKeyId = candidate;
                return true;
            }
        }

        accessKeyId = string.Empty;
        return false;
    }

    private static bool IsAwsAccessKeyId(string value)
    {
        if (value.Length != 20
            || !HasAwsAccessKeyIdPrefix(value))
        {
            return false;
        }

        for (int i = 4; i < value.Length; i++)
        {
            if (value[i] is not (>= 'A' and <= 'Z' or >= '2' and <= '7'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasAwsAccessKeyIdPrefix(string value)
    {
        return value.StartsWith("AKIA", StringComparison.Ordinal)
            || value.StartsWith("ASIA", StringComparison.Ordinal)
            || value.StartsWith("ABIA", StringComparison.Ordinal)
            || value.StartsWith("ACCA", StringComparison.Ordinal)
            || (value.StartsWith("A3T", StringComparison.Ordinal)
                && value.Length >= 4
                && IsAsciiAlphaNumeric(value[3]));
    }

    private static string GetAwsResourceType(string accessKeyId)
    {
        return accessKeyId[..4] switch
        {
            "ABIA" => "AWS STS service bearer token",
            "ACCA" => "context-specific credential",
            "AKIA" => "access key",
            "ASIA" => "temporary STS access key",
            _ => "access key",
        };
    }

    private static bool TryReadGcpServiceAccountEvidence(string json, out string projectId, out string clientEmail, out string privateKeyId)
    {
        projectId = string.Empty;
        clientEmail = string.Empty;
        privateKeyId = string.Empty;
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !TryGetJsonString(document.RootElement, "project_id", out projectId)
                || !TryGetJsonString(document.RootElement, "client_email", out clientEmail)
                || !TryGetJsonString(document.RootElement, "private_key_id", out privateKeyId))
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

    private static bool IsAsciiAlphaNumeric(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9';
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
