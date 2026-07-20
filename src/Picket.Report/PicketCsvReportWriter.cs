using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native CSV reports with stable finding metadata columns.
/// </summary>
public static class PicketCsvReportWriter
{
    private static readonly string[] s_columns =
    [
        "Schema",
        "RuleID",
        "Description",
        "File",
        "SymlinkFile",
        "StartLine",
        "EndLine",
        "StartColumn",
        "EndColumn",
        "PositionKind",
        "Secret",
        "SecretSha256",
        "Match",
        "MatchSha256",
        "BlobSha256",
        "DecodePath",
        "Line",
        "Commit",
        "Entropy",
        "RandomnessModel",
        "RandomnessScore",
        "RandomnessClassification",
        "RandomnessSampleOffset",
        "RandomnessSampleLength",
        "RandomnessAlphabet",
        "RandomnessLengthScore",
        "RandomnessNormalizedEntropy",
        "RandomnessExpectedDistinctRatio",
        "RandomnessTransitionDiversity",
        "RandomnessLongestRunRatio",
        "RandomnessSequentialPairRatio",
        "RandomnessRepeatedPatternRatio",
        "RandomnessCommonBigramRatio",
        "RandomnessCharacterClassBalance",
        "RandomnessEncodedTextSignal",
        "RandomnessPlaceholderSignal",
        "RandomnessSignals",
        "Author",
        "Email",
        "Date",
        "Message",
        "Fingerprint",
        "ValidationState",
        "Severity",
        "Confidence",
        "RulePack",
        "Provider",
        "DocumentationUrl",
        "ProvenanceType",
        "BaselineStatus",
        "IgnoreReason",
        "Tags",
        "Link",
    ];

    /// <summary>
    /// Writes findings to a deterministic UTF-8 CSV string.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <returns>A CSV report with a header row and trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        return Write(findings, []);
    }

    /// <summary>
    /// Writes findings to a deterministic UTF-8 CSV string with rule-derived metadata.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A CSV report with a header row and trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        WriteRow(builder, s_columns);
        Dictionary<string, SecretRule> ruleIndex = PicketFindingMetadata.CreateRuleIndex(rules);
        for (int i = 0; i < findings.Count; i++)
        {
            WriteFinding(builder, findings[i], PicketFindingMetadata.FindRule(ruleIndex, findings[i]));
        }

        return builder.ToString();
    }

    private static void WriteFinding(StringBuilder builder, Finding finding, SecretRule? rule)
    {
        SecretRandomnessAssessment? randomness = finding.Randomness;
        SecretRandomnessFeatures? features = randomness?.Features;
        string[] row =
        [
            "picket.finding.v1",
            finding.RuleID,
            finding.Description,
            finding.File,
            finding.SymlinkFile,
            finding.StartLine.ToString(CultureInfo.InvariantCulture),
            finding.EndLine.ToString(CultureInfo.InvariantCulture),
            finding.StartColumn.ToString(CultureInfo.InvariantCulture),
            finding.EndColumn.ToString(CultureInfo.InvariantCulture),
            PicketFindingMetadata.CreatePositionKind(finding),
            finding.Secret,
            PicketFindingMetadata.CreateSecretSha256(finding),
            finding.Match,
            PicketFindingMetadata.CreateMatchSha256(finding),
            PicketFindingMetadata.CreateBlobSha256(finding),
            string.Join('>', PicketFindingMetadata.CreateDecodePath(finding)),
            finding.Line,
            finding.Commit,
            finding.Entropy.ToString("G17", CultureInfo.InvariantCulture),
            randomness?.Model ?? string.Empty,
            randomness is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(randomness.Score),
            randomness?.Classification ?? string.Empty,
            features?.SampleOffset.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            features?.SampleLength.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            features?.Alphabet ?? string.Empty,
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.LengthScore),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.NormalizedEntropy),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.ExpectedDistinctRatio),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.TransitionDiversity),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.LongestRunRatio),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.SequentialPairRatio),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.RepeatedPatternRatio),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.CommonBigramRatio),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.CharacterClassBalance),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.EncodedTextSignal),
            features is null ? string.Empty : PicketFindingMetadata.FormatRandomnessNumber(features.PlaceholderSignal),
            randomness is null ? string.Empty : string.Join(' ', randomness.Signals),
            finding.Author,
            finding.Email,
            finding.Date,
            finding.Message,
            PicketFindingMetadata.CreateFingerprint(finding),
            PicketFindingMetadata.CreateValidationState(finding),
            PicketFindingMetadata.CreateSeverity(rule),
            PicketFindingMetadata.CreateConfidence(rule),
            PicketFindingMetadata.CreateRulePack(rule),
            PicketFindingMetadata.CreateProvider(rule),
            PicketFindingMetadata.CreateDocumentationUrl(rule),
            PicketFindingMetadata.CreateProvenanceType(finding),
            PicketFindingMetadata.BaselineStatus,
            PicketFindingMetadata.IgnoreReason,
            string.Join(' ', finding.Tags),
            finding.Link,
        ];
        WriteRow(builder, row);
    }

    private static void WriteRow(StringBuilder builder, string[] fields)
    {
        for (int i = 0; i < fields.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            AppendField(builder, fields[i]);
        }

        builder.Append('\n');
    }

    private static void AppendField(StringBuilder builder, string value)
    {
        bool neutralizeFormula = StartsWithFormulaPrefix(value);
        if (!neutralizeFormula && !NeedsQuotes(value))
        {
            builder.Append(value);
            return;
        }

        builder.Append('"');
        if (neutralizeFormula)
        {
            builder.Append('\'');
        }

        foreach (char ch in value)
        {
            if (ch == '"')
            {
                builder.Append("\"\"");
            }
            else
            {
                builder.Append(ch);
            }
        }

        builder.Append('"');
    }

    private static bool StartsWithFormulaPrefix(string value)
    {
        return value.Length != 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r';
    }

    private static bool NeedsQuotes(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        char first = value[0];
        if (first is ' ' or '\t')
        {
            return true;
        }

        return value.Contains(',')
            || value.Contains('"')
            || value.Contains('\r')
            || value.Contains('\n');
    }
}
