using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native JSON Lines reports with one finding per line.
/// </summary>
public static class PicketJsonlReportWriter
{
    /// <summary>
    /// Writes findings to compact JSON Lines.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <returns>A JSON Lines report, or an empty string when there are no findings.</returns>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        return Write(findings, []);
    }

    /// <summary>
    /// Writes findings to compact JSON Lines with rule-derived metadata.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A JSON Lines report, or an empty string when there are no findings.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        if (findings.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        Dictionary<string, SecretRule> ruleIndex = PicketFindingMetadata.CreateRuleIndex(rules);
        foreach (Finding finding in findings)
        {
            WriteFinding(builder, finding, PicketFindingMetadata.FindRule(ruleIndex, finding));
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static void WriteFinding(StringBuilder builder, Finding finding, SecretRule? rule)
    {
        builder.Append('{');
        WriteString(builder, "schema", "picket.finding.v1", comma: true);
        WriteString(builder, "ruleId", finding.RuleID, comma: true);
        WriteString(builder, "description", finding.Description, comma: true);
        WriteString(builder, "file", finding.File, comma: true);
        WriteString(builder, "symlinkFile", finding.SymlinkFile, comma: true);
        WriteNumber(builder, "startLine", finding.StartLine, comma: true);
        WriteNumber(builder, "endLine", finding.EndLine, comma: true);
        WriteNumber(builder, "startColumn", finding.StartColumn, comma: true);
        WriteNumber(builder, "endColumn", finding.EndColumn, comma: true);
        WriteString(builder, "match", finding.Match, comma: true);
        WriteString(builder, "secret", finding.Secret, comma: true);
        WriteString(builder, "secretSha256", PicketFindingMetadata.CreateSecretSha256(finding), comma: true);
        WriteString(builder, "matchSha256", PicketFindingMetadata.CreateMatchSha256(finding), comma: true);
        WriteString(builder, "blobSha256", PicketFindingMetadata.CreateBlobSha256(finding), comma: true);
        WriteString(builder, "line", finding.Line, comma: true);
        WriteString(builder, "commit", finding.Commit, comma: true);
        WriteNumber(builder, "entropy", finding.Entropy, comma: true);
        WriteRandomness(builder, finding.Randomness, comma: true);
        WriteString(builder, "author", finding.Author, comma: true);
        WriteString(builder, "email", finding.Email, comma: true);
        WriteString(builder, "date", finding.Date, comma: true);
        WriteString(builder, "message", finding.Message, comma: true);
        WriteArray(builder, "tags", finding.Tags, comma: true);
        WriteString(builder, "fingerprint", PicketFindingMetadata.CreateFingerprint(finding), comma: true);
        WriteString(builder, "validationState", PicketFindingMetadata.CreateValidationState(finding), comma: true);
        WriteString(builder, "severity", PicketFindingMetadata.CreateSeverity(rule), comma: true);
        WriteString(builder, "confidence", PicketFindingMetadata.CreateConfidence(rule), comma: true);
        WriteString(builder, "rulePack", PicketFindingMetadata.CreateRulePack(rule), comma: true);
        WriteString(builder, "provider", PicketFindingMetadata.CreateProvider(rule), comma: true);
        WriteString(builder, "documentationUrl", PicketFindingMetadata.CreateDocumentationUrl(rule), comma: true);
        WriteProvenance(builder, finding, comma: true);
        WriteArray(builder, "decodePath", PicketFindingMetadata.CreateDecodePath(finding), comma: true);
        WriteString(builder, "baselineStatus", PicketFindingMetadata.BaselineStatus, comma: true);
        WriteString(builder, "ignoreReason", PicketFindingMetadata.IgnoreReason, comma: true);
        WriteArray(builder, "remediationLinks", PicketFindingMetadata.CreateRemediationLinks(rule), comma: true);
        WriteString(builder, "link", finding.Link, comma: false);
        builder.Append('}');
    }

    private static void WriteProvenance(StringBuilder builder, Finding finding, bool comma)
    {
        WritePropertyName(builder, "provenance");
        builder.Append('{');
        WriteString(builder, "type", PicketFindingMetadata.CreateProvenanceType(finding), comma: true);
        WriteString(builder, "path", PicketFindingMetadata.CreateLocationPath(finding), comma: true);
        WriteString(builder, "commit", finding.Commit, comma: false);
        builder.Append('}');
        WriteComma(builder, comma);
    }

    private static void WriteRandomness(StringBuilder builder, SecretRandomnessAssessment? assessment, bool comma)
    {
        WritePropertyName(builder, "randomness");
        if (assessment is null)
        {
            builder.Append("null");
            WriteComma(builder, comma);
            return;
        }

        SecretRandomnessFeatures features = assessment.Features;
        builder.Append('{');
        WriteString(builder, "model", assessment.Model, comma: true);
        WriteRandomnessNumber(builder, "score", assessment.Score, comma: true);
        WriteString(builder, "classification", assessment.Classification, comma: true);
        WriteNumber(builder, "sampleOffset", features.SampleOffset, comma: true);
        WriteNumber(builder, "sampleLength", features.SampleLength, comma: true);
        WriteString(builder, "alphabet", features.Alphabet, comma: true);
        WriteRandomnessNumber(builder, "lengthScore", features.LengthScore, comma: true);
        WriteRandomnessNumber(builder, "normalizedEntropy", features.NormalizedEntropy, comma: true);
        WriteRandomnessNumber(builder, "expectedDistinctRatio", features.ExpectedDistinctRatio, comma: true);
        WriteRandomnessNumber(builder, "transitionDiversity", features.TransitionDiversity, comma: true);
        WriteRandomnessNumber(builder, "longestRunRatio", features.LongestRunRatio, comma: true);
        WriteRandomnessNumber(builder, "sequentialPairRatio", features.SequentialPairRatio, comma: true);
        WriteRandomnessNumber(builder, "repeatedPatternRatio", features.RepeatedPatternRatio, comma: true);
        WriteRandomnessNumber(builder, "commonBigramRatio", features.CommonBigramRatio, comma: true);
        WriteRandomnessNumber(builder, "characterClassBalance", features.CharacterClassBalance, comma: true);
        WriteRandomnessNumber(builder, "encodedTextSignal", features.EncodedTextSignal, comma: true);
        WriteRandomnessNumber(builder, "placeholderSignal", features.PlaceholderSignal, comma: true);
        WriteArray(builder, "signals", assessment.Signals, comma: false);
        builder.Append('}');
        WriteComma(builder, comma);
    }

    private static void WriteString(StringBuilder builder, string name, string value, bool comma)
    {
        WritePropertyName(builder, name);
        AppendJsonString(builder, value);
        WriteComma(builder, comma);
    }

    private static void WriteRandomnessNumber(StringBuilder builder, string name, double value, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append(PicketFindingMetadata.FormatRandomnessNumber(value));
        WriteComma(builder, comma);
    }

    private static void WriteNumber(StringBuilder builder, string name, int value, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        WriteComma(builder, comma);
    }

    private static void WriteNumber(StringBuilder builder, string name, double value, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append(ReportNumberFormatter.FormatJsonDouble(value));
        WriteComma(builder, comma);
    }

    private static void WriteArray(StringBuilder builder, string name, IReadOnlyList<string> values, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append('[');
        for (int i = 0; i < values.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            AppendJsonString(builder, values[i]);
        }

        builder.Append(']');
        WriteComma(builder, comma);
    }

    private static void WriteEmptyArray(StringBuilder builder, string name, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append("[]");
        WriteComma(builder, comma);
    }

    private static void WritePropertyName(StringBuilder builder, string name)
    {
        AppendJsonString(builder, name);
        builder.Append(':');
    }

    private static void WriteComma(StringBuilder builder, bool comma)
    {
        if (comma)
        {
            builder.Append(',');
        }
    }

    private static void AppendJsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (rune.Value < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(rune.Value.ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(rune.ToString());
                    }

                    break;
            }
        }

        builder.Append('"');
    }
}
