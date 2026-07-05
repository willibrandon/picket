using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Performs safe offline validation that does not contact providers or exfiltrate secret material.
/// </summary>
public static class OfflineSecretValidator
{
    /// <summary>
    /// Validates one finding without contacting external services.
    /// </summary>
    /// <param name="finding">The finding to validate.</param>
    /// <returns>The validation result.</returns>
    public static SecretValidationResult Validate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string secret = finding.Secret.Length == 0 ? finding.Match : finding.Secret;
        if (secret.Length == 0)
        {
            return Unknown();
        }

        if (IsTestCredential(secret))
        {
            return new SecretValidationResult(SecretValidationState.TestCredential, "known test or placeholder marker");
        }

        return finding.RuleID switch
        {
            "aws-access-token" => ValidateAwsAccessKeyId(secret),
            "github-app-token" => ValidateGitHubClassicToken(secret, "ghu_", "ghs_"),
            "github-fine-grained-pat" => ValidateGitHubFineGrainedToken(secret),
            "github-oauth" => ValidateGitHubClassicToken(secret, "gho_"),
            "github-pat" => ValidateGitHubClassicToken(secret, "ghp_"),
            "github-refresh-token" => ValidateGitHubClassicToken(secret, "ghr_"),
            "private-key" => ValidatePrivateKeyEnvelope(finding.Match),
            _ => Unknown(),
        };
    }

    /// <summary>
    /// Returns a finding annotated with an offline validation state.
    /// </summary>
    /// <param name="finding">The finding to annotate.</param>
    /// <returns>The original finding when it is already annotated; otherwise an annotated copy.</returns>
    public static Finding Annotate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (finding.ValidationState.Length != 0
            && !finding.ValidationState.Equals("unknown", StringComparison.Ordinal))
        {
            return finding;
        }

        SecretValidationResult result = Validate(finding);
        if (result.State == SecretValidationState.Unknown && finding.ValidationState.Length != 0)
        {
            return finding;
        }

        return CopyWithValidationState(finding, result.ReportValue);
    }

    /// <summary>
    /// Returns findings annotated with offline validation states.
    /// </summary>
    /// <param name="findings">The findings to annotate.</param>
    /// <returns>A list of annotated findings in the same order.</returns>
    public static List<Finding> AnnotateAll(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var annotated = new List<Finding>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            annotated.Add(Annotate(findings[i]));
        }

        return annotated;
    }

    private static SecretValidationResult ValidateAwsAccessKeyId(string secret)
    {
        if (secret.Length != 20 || !HasAnyPrefix(secret, "AKIA", "ASIA", "ABIA", "ACCA") && !HasA3TPrefix(secret))
        {
            return Invalid("invalid AWS access key ID shape");
        }

        for (int i = 4; i < secret.Length; i++)
        {
            if (!IsAwsAccessKeyIdSuffixCharacter(secret[i]))
            {
                return Invalid("invalid AWS access key ID alphabet");
            }
        }

        return StructurallyValid("valid AWS access key ID shape");
    }

    private static SecretValidationResult ValidateGitHubClassicToken(string secret, params string[] prefixes)
    {
        if (secret.Length != 40 || !HasAnyPrefix(secret, prefixes))
        {
            return Invalid("invalid GitHub token shape");
        }

        return HasAsciiAlphaNumericSuffix(secret, 4)
            ? StructurallyValid("valid GitHub token shape")
            : Invalid("invalid GitHub token alphabet");
    }

    private static SecretValidationResult ValidateGitHubFineGrainedToken(string secret)
    {
        const string Prefix = "github_pat_";
        if (secret.Length != Prefix.Length + 82 || !secret.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return Invalid("invalid GitHub fine-grained token shape");
        }

        for (int i = Prefix.Length; i < secret.Length; i++)
        {
            if (!IsWordCharacter(secret[i]))
            {
                return Invalid("invalid GitHub fine-grained token alphabet");
            }
        }

        return StructurallyValid("valid GitHub fine-grained token shape");
    }

    private static SecretValidationResult ValidatePrivateKeyEnvelope(string match)
    {
        return match.Contains("-----BEGIN", StringComparison.Ordinal)
            && match.Contains("PRIVATE KEY", StringComparison.Ordinal)
            && match.Contains("-----END", StringComparison.Ordinal)
            ? StructurallyValid("valid private key envelope")
            : Invalid("invalid private key envelope");
    }

    private static Finding CopyWithValidationState(Finding finding, string validationState)
    {
        return new Finding(
            finding.RuleID,
            finding.Description,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            finding.File,
            finding.SymlinkFile,
            finding.Commit,
            finding.Entropy,
            finding.Author,
            finding.Email,
            finding.Date,
            finding.Message,
            finding.Tags,
            finding.Fingerprint,
            finding.Line,
            finding.Link,
            finding.SecretSha256,
            finding.MatchSha256,
            validationState);
    }

    private static bool IsTestCredential(string secret)
    {
        return secret.Contains("example", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("dummy", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("fake", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("placeholder", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("changeme", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("changeit", StringComparison.OrdinalIgnoreCase)
            || HasRepeatedSingleCharacter(secret);
    }

    private static bool HasRepeatedSingleCharacter(string secret)
    {
        if (secret.Length < 8)
        {
            return false;
        }

        char first = secret[0];
        for (int i = 1; i < secret.Length; i++)
        {
            if (secret[i] != first)
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasAnyPrefix(string secret, params string[] prefixes)
    {
        for (int i = 0; i < prefixes.Length; i++)
        {
            if (secret.StartsWith(prefixes[i], StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasA3TPrefix(string secret)
    {
        return secret.StartsWith("A3T", StringComparison.Ordinal)
            && secret.Length >= 4
            && IsAsciiAlphaNumeric(secret[3]);
    }

    private static bool IsAwsAccessKeyIdSuffixCharacter(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= '2' and <= '7';
    }

    private static bool HasAsciiAlphaNumericSuffix(string secret, int start)
    {
        for (int i = start; i < secret.Length; i++)
        {
            if (!IsAsciiAlphaNumeric(secret[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsWordCharacter(char value)
    {
        return IsAsciiAlphaNumeric(value) || value == '_';
    }

    private static bool IsAsciiAlphaNumeric(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9';
    }

    private static SecretValidationResult Unknown()
    {
        return new SecretValidationResult(SecretValidationState.Unknown);
    }

    private static SecretValidationResult StructurallyValid(string reason)
    {
        return new SecretValidationResult(SecretValidationState.StructurallyValid, reason);
    }

    private static SecretValidationResult Invalid(string reason)
    {
        return new SecretValidationResult(SecretValidationState.Invalid, reason);
    }
}
