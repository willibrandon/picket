namespace Picket.Engine;

/// <summary>
/// Attaches native randomness assessments and applies explicit per-rule score thresholds.
/// </summary>
public static class SecretRandomnessFindingProcessor
{
    /// <summary>
    /// Enriches findings with deterministic randomness metadata and removes findings below an explicit rule threshold.
    /// </summary>
    /// <param name="findings">The findings to process.</param>
    /// <param name="rules">The compiled rules that produced the findings.</param>
    /// <returns>The processed findings.</returns>
    public static List<Finding> Apply(IReadOnlyList<Finding> findings, CompiledRuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);
        if (findings.Count == 0)
        {
            return findings as List<Finding> ?? [];
        }

        if (!rules.HasRandomnessThresholds && AllHaveCurrentAssessments(findings))
        {
            return findings as List<Finding> ?? [.. findings];
        }

        var processed = new List<Finding>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            SecretRandomnessAssessment? assessment = IsCurrentAssessment(finding.Randomness)
                ? finding.Randomness
                : CreateAssessment(finding.Secret);
            if (assessment is not null
                && rules.TryGetRandomnessThreshold(finding.RuleID, out double threshold)
                && threshold > assessment.Score)
            {
                continue;
            }

            processed.Add(assessment is null || ReferenceEquals(assessment, finding.Randomness)
                ? finding
                : CopyWithAssessment(finding, assessment));
        }

        return processed;
    }

    private static bool AllHaveCurrentAssessments(IReadOnlyList<Finding> findings)
    {
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            if (CanCreateAssessment(finding.Secret)
                && !IsCurrentAssessment(finding.Randomness))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsCurrentAssessment(SecretRandomnessAssessment? assessment)
    {
        return assessment is not null
            && assessment.Model.Equals(SecretRandomnessScorer.ModelVersion, StringComparison.Ordinal);
    }

    private static SecretRandomnessAssessment? CreateAssessment(string secret)
    {
        if (!CanCreateAssessment(secret))
        {
            return null;
        }

        return SecretRandomnessScorer.Assess(secret);
    }

    private static bool CanCreateAssessment(string secret)
    {
        return secret.Length != 0
            && !secret.Equals("REDACTED", StringComparison.Ordinal);
    }

    private static Finding CopyWithAssessment(Finding finding, SecretRandomnessAssessment assessment)
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
            finding.ValidationState,
            finding.BlobSha256,
            finding.DecodePath,
            assessment,
            finding.PositionKind);
    }
}
