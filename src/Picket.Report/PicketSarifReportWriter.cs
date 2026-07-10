using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native SARIF 2.1.0 reports for code-scanning systems.
/// </summary>
public static class PicketSarifReportWriter
{
    private const string SchemaUri = "https://json.schemastore.org/sarif-2.1.0.json";
    private const string ToolName = "picket";
    private const string ToolFullName = "Picket secrets scanner";
    private const string ToolInformationUri = "https://github.com/willibrandon/picket";
    private const string ResultLevel = "error";

    /// <summary>
    /// Writes findings and ordered rules to a deterministic SARIF JSON string.
    /// </summary>
    /// <param name="findings">The findings to report.</param>
    /// <param name="rules">The ordered rules from the active configuration.</param>
    /// <returns>The SARIF JSON report with a trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        builder.Append("{\n");
        WriteStringProperty(builder, 1, "$schema", SchemaUri, comma: true);
        WriteStringProperty(builder, 1, "version", "2.1.0", comma: true);
        WritePropertyName(builder, 1, "runs");
        builder.Append(" [\n");
        WriteRun(builder, rules, findings);
        builder.Append('\n');
        Indent(builder, 1);
        builder.Append("]\n");
        builder.Append("}\n");
        return builder.ToString();
    }

    private static void WriteRun(StringBuilder builder, IReadOnlyList<SecretRule> rules, IReadOnlyList<Finding> findings)
    {
        Indent(builder, 2);
        builder.Append("{\n");
        WriteTool(builder, rules);
        builder.Append(",\n");
        WriteResults(builder, findings, PicketFindingMetadata.CreateRuleIndex(rules));
        builder.Append('\n');
        Indent(builder, 2);
        builder.Append('}');
    }

    private static void WriteTool(StringBuilder builder, IReadOnlyList<SecretRule> rules)
    {
        WritePropertyName(builder, 3, "tool");
        builder.Append(" {\n");
        WritePropertyName(builder, 4, "driver");
        builder.Append(" {\n");
        WriteStringProperty(builder, 5, "name", ToolName, comma: true);
        WriteStringProperty(builder, 5, "fullName", ToolFullName, comma: true);
        WriteStringProperty(builder, 5, "informationUri", ToolInformationUri, comma: true);
        WritePropertyName(builder, 5, "rules");
        builder.Append(" [");
        if (rules.Count == 0)
        {
            builder.Append("]\n");
        }
        else
        {
            builder.Append('\n');
            for (int i = 0; i < rules.Count; i++)
            {
                WriteRule(builder, rules[i]);
                if (i + 1 < rules.Count)
                {
                    builder.Append(',');
                }

                builder.Append('\n');
            }

            Indent(builder, 5);
            builder.Append("]\n");
        }

        Indent(builder, 4);
        builder.Append("}\n");
        Indent(builder, 3);
        builder.Append('}');
    }

    private static void WriteRule(StringBuilder builder, SecretRule rule)
    {
        Indent(builder, 6);
        builder.Append("{\n");
        WriteStringProperty(builder, 7, "id", rule.Id, comma: true);
        WriteStringProperty(builder, 7, "name", rule.Id, comma: true);
        WriteMessageObject(builder, 7, "shortDescription", CreateRuleDescription(rule), comma: true);
        WriteDefaultConfiguration(builder, comma: true);
        WriteRuleProperties(builder, rule, comma: false);
        Indent(builder, 6);
        builder.Append('}');
    }

    private static void WriteDefaultConfiguration(StringBuilder builder, bool comma)
    {
        WritePropertyName(builder, 7, "defaultConfiguration");
        builder.Append(" {\n");
        WriteStringProperty(builder, 8, "level", ResultLevel, comma: false);
        Indent(builder, 7);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteRuleProperties(StringBuilder builder, SecretRule rule, bool comma)
    {
        WritePropertyName(builder, 7, "properties");
        builder.Append(" {\n");
        WriteStringProperty(builder, 8, "precision", PicketFindingMetadata.CreateConfidence(rule), comma: true);
        WriteStringProperty(builder, 8, "security-severity", PicketFindingMetadata.CreateSecuritySeverity(rule), comma: true);
        WriteStringProperty(builder, 8, "severity", PicketFindingMetadata.CreateSeverity(rule), comma: true);
        WriteStringProperty(builder, 8, "confidence", PicketFindingMetadata.CreateConfidence(rule), comma: true);
        WriteStringProperty(builder, 8, "rulePack", PicketFindingMetadata.CreateRulePack(rule), comma: true);
        WriteStringProperty(builder, 8, "provider", PicketFindingMetadata.CreateProvider(rule), comma: true);
        WriteStringProperty(builder, 8, "documentationUrl", PicketFindingMetadata.CreateDocumentationUrl(rule), comma: true);
        WriteProbabilityProperty(builder, 8, "randomnessThreshold", rule.RandomnessThreshold, comma: true);
        WritePropertyName(builder, 8, "tags");
        builder.Append(" [");
        WriteRuleTags(builder, rule.Tags);
        builder.Append('\n');
        Indent(builder, 8);
        builder.Append("]\n");
        Indent(builder, 7);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteRuleTags(StringBuilder builder, IReadOnlyList<string> tags)
    {
        bool wroteTag = false;
        for (int i = 0; i < tags.Count; i++)
        {
            WriteArrayString(builder, tags[i], ref wroteTag, depth: 9);
        }

        if (!HasTag(tags, "security"))
        {
            WriteArrayString(builder, "security", ref wroteTag, depth: 9);
        }

        if (!HasTag(tags, "secrets"))
        {
            WriteArrayString(builder, "secrets", ref wroteTag, depth: 9);
        }
    }

    private static bool HasTag(IReadOnlyList<string> tags, string expectedTag)
    {
        for (int i = 0; i < tags.Count; i++)
        {
            if (tags[i].Equals(expectedTag, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void WriteResults(StringBuilder builder, IReadOnlyList<Finding> findings, IReadOnlyDictionary<string, SecretRule> ruleIndex)
    {
        WritePropertyName(builder, 3, "results");
        builder.Append(" [");
        if (findings.Count == 0)
        {
            builder.Append(']');
            return;
        }

        builder.Append('\n');
        for (int i = 0; i < findings.Count; i++)
        {
            WriteResult(builder, findings[i], PicketFindingMetadata.FindRule(ruleIndex, findings[i]));
            if (i + 1 < findings.Count)
            {
                builder.Append(',');
            }

            builder.Append('\n');
        }

        Indent(builder, 3);
        builder.Append(']');
    }

    private static void WriteResult(StringBuilder builder, Finding finding, SecretRule? rule)
    {
        Indent(builder, 4);
        builder.Append("{\n");
        WriteStringProperty(builder, 5, "ruleId", finding.RuleID, comma: true);
        WriteStringProperty(builder, 5, "level", ResultLevel, comma: true);
        WriteStringProperty(builder, 5, "kind", "fail", comma: true);
        WriteMessageObject(builder, 5, "message", CreateResultMessage(finding), comma: true);
        WriteLocations(builder, finding, comma: true);
        WritePartialFingerprints(builder, finding, comma: true);
        WriteResultProperties(builder, finding, rule, comma: false);
        Indent(builder, 4);
        builder.Append('}');
    }

    private static void WriteLocations(StringBuilder builder, Finding finding, bool comma)
    {
        WritePropertyName(builder, 5, "locations");
        builder.Append(" [\n");
        Indent(builder, 6);
        builder.Append("{\n");
        WritePropertyName(builder, 7, "physicalLocation");
        builder.Append(" {\n");
        WritePropertyName(builder, 8, "artifactLocation");
        builder.Append(" {\n");
        WriteStringProperty(builder, 9, "uri", CreateLocationUri(finding), comma: false);
        Indent(builder, 8);
        builder.Append("},\n");
        WritePropertyName(builder, 8, "region");
        builder.Append(" {\n");
        WriteIntProperty(builder, 9, "startLine", finding.StartLine, comma: true);
        WriteIntProperty(builder, 9, "startColumn", finding.StartColumn, comma: true);
        WriteIntProperty(builder, 9, "endLine", finding.EndLine, comma: true);
        WriteIntProperty(builder, 9, "endColumn", finding.EndColumn, comma: true);
        WriteMessageObject(builder, 9, "snippet", finding.Line, comma: false);
        Indent(builder, 8);
        builder.Append("}\n");
        Indent(builder, 7);
        builder.Append("}\n");
        Indent(builder, 6);
        builder.Append("}\n");
        Indent(builder, 5);
        builder.Append(']');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WritePartialFingerprints(StringBuilder builder, Finding finding, bool comma)
    {
        WritePropertyName(builder, 5, "partialFingerprints");
        builder.Append(" {\n");
        WriteStringProperty(builder, 6, "picketFingerprint", CreateFingerprint(finding), comma: false);
        Indent(builder, 5);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteResultProperties(StringBuilder builder, Finding finding, SecretRule? rule, bool comma)
    {
        WritePropertyName(builder, 5, "properties");
        builder.Append(" {\n");
        WriteStringProperty(builder, 6, "schema", "picket.finding.v1", comma: true);
        WriteStringProperty(builder, 6, "fingerprint", CreateFingerprint(finding), comma: true);
        WriteStringProperty(builder, 6, "commit", finding.Commit, comma: true);
        WriteNumberProperty(builder, 6, "entropy", finding.Entropy, comma: true);
        WriteRandomnessProperty(builder, finding.Randomness, comma: true);
        WriteStringProperty(builder, 6, "secretSha256", PicketFindingMetadata.CreateSecretSha256(finding), comma: true);
        WriteStringProperty(builder, 6, "matchSha256", PicketFindingMetadata.CreateMatchSha256(finding), comma: true);
        WriteStringProperty(builder, 6, "blobSha256", PicketFindingMetadata.CreateBlobSha256(finding), comma: true);
        WriteStringProperty(builder, 6, "validationState", PicketFindingMetadata.CreateValidationState(finding), comma: true);
        WriteStringProperty(builder, 6, "severity", PicketFindingMetadata.CreateSeverity(rule), comma: true);
        WriteStringProperty(builder, 6, "confidence", PicketFindingMetadata.CreateConfidence(rule), comma: true);
        WriteStringProperty(builder, 6, "rulePack", PicketFindingMetadata.CreateRulePack(rule), comma: true);
        WriteStringProperty(builder, 6, "provider", PicketFindingMetadata.CreateProvider(rule), comma: true);
        WriteStringProperty(builder, 6, "documentationUrl", PicketFindingMetadata.CreateDocumentationUrl(rule), comma: true);
        WriteStringProperty(builder, 6, "provenanceType", PicketFindingMetadata.CreateProvenanceType(finding), comma: true);
        WriteStringProperty(builder, 6, "baselineStatus", PicketFindingMetadata.BaselineStatus, comma: true);
        WriteStringProperty(builder, 6, "ignoreReason", PicketFindingMetadata.IgnoreReason, comma: true);
        WriteArrayProperty(builder, 6, "decodePath", PicketFindingMetadata.CreateDecodePath(finding), comma: true);
        WriteArrayProperty(builder, 6, "remediationLinks", PicketFindingMetadata.CreateRemediationLinks(rule), comma: true);
        WriteArrayProperty(builder, 6, "tags", finding.Tags, comma: true);
        WriteStringProperty(builder, 6, "link", finding.Link, comma: false);
        Indent(builder, 5);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteRandomnessProperty(StringBuilder builder, SecretRandomnessAssessment? assessment, bool comma)
    {
        WritePropertyName(builder, 6, "randomness");
        builder.Append(' ');
        if (assessment is null)
        {
            builder.Append("null");
            WriteComma(builder, comma);
            builder.Append('\n');
            return;
        }

        SecretRandomnessFeatures features = assessment.Features;
        builder.Append("{\n");
        WriteStringProperty(builder, 7, "model", assessment.Model, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "score", assessment.Score, comma: true);
        WriteStringProperty(builder, 7, "classification", assessment.Classification, comma: true);
        WriteIntProperty(builder, 7, "sampleOffset", features.SampleOffset, comma: true);
        WriteIntProperty(builder, 7, "sampleLength", features.SampleLength, comma: true);
        WriteStringProperty(builder, 7, "alphabet", features.Alphabet, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "lengthScore", features.LengthScore, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "normalizedEntropy", features.NormalizedEntropy, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "expectedDistinctRatio", features.ExpectedDistinctRatio, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "transitionDiversity", features.TransitionDiversity, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "longestRunRatio", features.LongestRunRatio, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "sequentialPairRatio", features.SequentialPairRatio, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "repeatedPatternRatio", features.RepeatedPatternRatio, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "commonBigramRatio", features.CommonBigramRatio, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "characterClassBalance", features.CharacterClassBalance, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "encodedTextSignal", features.EncodedTextSignal, comma: true);
        WriteRandomnessNumberProperty(builder, 7, "placeholderSignal", features.PlaceholderSignal, comma: true);
        WriteArrayProperty(builder, 7, "signals", assessment.Signals, comma: false);
        Indent(builder, 6);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static string CreateRuleDescription(SecretRule rule)
    {
        return rule.Description.Length == 0 ? rule.Id : rule.Description;
    }

    private static string CreateResultMessage(Finding finding)
    {
        string description = finding.Description.Length == 0 ? finding.RuleID : $"{finding.RuleID}: {finding.Description}";
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{description} detected a secret in {CreateLocationUri(finding)} on line {finding.StartLine}.");
    }

    private static string CreateFingerprint(Finding finding)
    {
        return PicketFindingMetadata.CreateFingerprint(finding);
    }

    private static string CreateLocationUri(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    private static void WriteMessageObject(StringBuilder builder, int depth, string name, string text, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(" {\n");
        WriteStringProperty(builder, depth + 1, "text", text, comma: false);
        Indent(builder, depth);
        builder.Append('}');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteArrayProperty(StringBuilder builder, int depth, string name, IReadOnlyList<string> values, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(" [");
        if (values.Count == 0)
        {
            builder.Append(']');
            WriteComma(builder, comma);
            builder.Append('\n');
            return;
        }

        builder.Append('\n');
        for (int i = 0; i < values.Count; i++)
        {
            Indent(builder, depth + 1);
            AppendJsonString(builder, values[i]);
            if (i + 1 < values.Count)
            {
                builder.Append(',');
            }

            builder.Append('\n');
        }

        Indent(builder, depth);
        builder.Append(']');
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteArrayString(StringBuilder builder, string value, ref bool wroteValue, int depth)
    {
        if (wroteValue)
        {
            builder.Append(',');
        }

        builder.Append('\n');
        Indent(builder, depth);
        AppendJsonString(builder, value);
        wroteValue = true;
    }

    private static void WriteStringProperty(StringBuilder builder, int depth, string name, string value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        AppendJsonString(builder, value);
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteIntProperty(StringBuilder builder, int depth, string name, int value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteNumberProperty(StringBuilder builder, int depth, string name, double value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        builder.Append(ReportNumberFormatter.FormatJsonDouble(value));
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteRandomnessNumberProperty(StringBuilder builder, int depth, string name, double value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        builder.Append(PicketFindingMetadata.FormatRandomnessNumber(value));
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WriteProbabilityProperty(StringBuilder builder, int depth, string name, double value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        builder.Append(PicketFindingMetadata.FormatProbability(value));
        WriteComma(builder, comma);
        builder.Append('\n');
    }

    private static void WritePropertyName(StringBuilder builder, int depth, string name)
    {
        Indent(builder, depth);
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
                case '<':
                    builder.Append("\\u003c");
                    break;
                case '>':
                    builder.Append("\\u003e");
                    break;
                case '&':
                    builder.Append("\\u0026");
                    break;
                case 0x2028:
                    builder.Append("\\u2028");
                    break;
                case 0x2029:
                    builder.Append("\\u2029");
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

    private static void Indent(StringBuilder builder, int depth)
    {
        builder.Append(' ', depth);
    }
}
