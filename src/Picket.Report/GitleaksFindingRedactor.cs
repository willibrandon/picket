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
        ArgumentNullException.ThrowIfNull(findings);
        ValidateRedactionPercent(redactionPercent);

        var redacted = new List<Finding>(findings.Count);
        foreach (Finding finding in findings)
        {
            redacted.Add(Redact(finding, redactionPercent));
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
        ArgumentNullException.ThrowIfNull(finding);
        ValidateRedactionPercent(redactionPercent);

        if (redactionPercent == 0 || finding.Secret.Length == 0)
        {
            return finding;
        }

        string secret = MaskSecret(finding.Secret, redactionPercent);
        string match = finding.Match.Replace(finding.Secret, secret, StringComparison.Ordinal);
        string line = finding.Line.Replace(finding.Secret, secret, StringComparison.Ordinal);
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
            finding.MatchSha256.Length == 0 ? PicketFindingMetadata.CreateSha256(finding.Match) : finding.MatchSha256);
    }

    private static string MaskSecret(string secret, int redactionPercent)
    {
        if (redactionPercent >= 100)
        {
            return "REDACTED";
        }

        int visibleLength = (int)Math.Round(secret.Length * (100 - redactionPercent) / 100.0, MidpointRounding.ToEven);
        return string.Concat(secret.AsSpan(0, visibleLength), "...");
    }

    private static void ValidateRedactionPercent(int redactionPercent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(redactionPercent);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(redactionPercent, 100);
    }
}
