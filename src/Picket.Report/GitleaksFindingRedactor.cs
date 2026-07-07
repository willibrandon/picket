using Picket.Engine;

namespace Picket.Report;

/// <summary>
/// Applies Gitleaks-compatible finding redaction before reports are written.
/// </summary>
public static class GitleaksFindingRedactor
{
    /// <summary>
    /// Redacts secrets in each finding using the supplied percentage.
    /// </summary>
    /// <param name="findings">The findings to redact.</param>
    /// <param name="redactionPercent">The redaction percentage from 0 through 100.</param>
    /// <returns>The redacted findings.</returns>
    public static List<Finding> Redact(IReadOnlyList<Finding> findings, int redactionPercent)
    {
        return Redact(findings, redactionPercent, requirePartialMask: false);
    }

    /// <summary>
    /// Redacts secrets in each finding using the supplied percentage.
    /// </summary>
    /// <param name="findings">The findings to redact.</param>
    /// <param name="redactionPercent">The redaction percentage from 0 through 100.</param>
    /// <param name="requirePartialMask">A value indicating whether a non-zero redaction percentage must mask at least one character.</param>
    /// <returns>The redacted findings.</returns>
    public static List<Finding> Redact(IReadOnlyList<Finding> findings, int redactionPercent, bool requirePartialMask)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ValidateRedactionPercent(redactionPercent);

        var redacted = new List<Finding>(findings.Count);
        foreach (Finding finding in findings)
        {
            redacted.Add(Redact(finding, redactionPercent, requirePartialMask));
        }

        return redacted;
    }

    /// <summary>
    /// Redacts a finding secret using the supplied percentage.
    /// </summary>
    /// <param name="finding">The finding to redact.</param>
    /// <param name="redactionPercent">The redaction percentage from 0 through 100.</param>
    /// <returns>The redacted finding.</returns>
    public static Finding Redact(Finding finding, int redactionPercent)
    {
        return Redact(finding, redactionPercent, requirePartialMask: false);
    }

    /// <summary>
    /// Redacts a finding secret using the supplied percentage.
    /// </summary>
    /// <param name="finding">The finding to redact.</param>
    /// <param name="redactionPercent">The redaction percentage from 0 through 100.</param>
    /// <param name="requirePartialMask">A value indicating whether a non-zero redaction percentage must mask at least one character.</param>
    /// <returns>The redacted finding.</returns>
    public static Finding Redact(Finding finding, int redactionPercent, bool requirePartialMask)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ValidateRedactionPercent(redactionPercent);

        if (redactionPercent == 0 || finding.Secret.Length == 0)
        {
            return finding;
        }

        string secret = MaskSecret(finding.Secret, redactionPercent, requirePartialMask);
        string match = finding.Match.Replace(finding.Secret, secret, StringComparison.Ordinal);
        string line = RedactLine(finding, secret);
        return new Finding(
            finding.RuleID,
            finding.Description,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            match,
            secret,
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
            line,
            finding.Link,
            finding.SecretSha256.Length == 0 ? PicketFindingMetadata.CreateSha256(finding.Secret) : finding.SecretSha256,
            finding.MatchSha256.Length == 0 ? PicketFindingMetadata.CreateSha256(finding.Match) : finding.MatchSha256,
            finding.ValidationState,
            finding.BlobSha256,
            finding.DecodePath);
    }

    private static string RedactLine(Finding finding, string redactedSecret)
    {
        if (finding.DecodePath.Count != 0)
        {
            return redactedSecret;
        }

        return finding.Line.Replace(finding.Secret, redactedSecret, StringComparison.Ordinal);
    }

    private static string MaskSecret(string secret, int redactionPercent, bool requirePartialMask)
    {
        if (redactionPercent >= 100)
        {
            return "REDACTED";
        }

        int visibleLength = (int)Math.Round(secret.Length * (100 - redactionPercent) / 100.0, MidpointRounding.ToEven);
        if (requirePartialMask && redactionPercent > 0 && visibleLength >= secret.Length)
        {
            visibleLength = secret.Length - 1;
        }

        return string.Concat(secret.AsSpan(0, visibleLength), "...");
    }

    private static void ValidateRedactionPercent(int redactionPercent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(redactionPercent);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(redactionPercent, 100);
    }
}
