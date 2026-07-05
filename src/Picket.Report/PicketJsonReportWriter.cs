using System.Globalization;
using System.Text;
using Picket.Engine;
using Picket.Rules;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native JSON reports with schema and rule metadata.
/// </summary>
public static class PicketJsonReportWriter
{
    /// <summary>
    /// Writes findings and rule metadata to a deterministic JSON report.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A JSON report with a trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        builder.Append('{');
        WriteString(builder, "schema", "picket.report.v1", comma: true);
        WriteTool(builder, comma: true);
        WriteRules(builder, rules, comma: true);
        WriteFindings(builder, findings, comma: false);
        builder.Append('}');
        builder.Append('\n');
        return builder.ToString();
    }

    private static void WriteTool(StringBuilder builder, bool comma)
    {
        WritePropertyName(builder, "tool");
        builder.Append('{');
        WriteString(builder, "name", "picket", comma: false);
        builder.Append('}');
        WriteComma(builder, comma);
    }

    private static void WriteRules(StringBuilder builder, IReadOnlyList<SecretRule> rules, bool comma)
    {
        WritePropertyName(builder, "rules");
        builder.Append('[');
        for (int i = 0; i < rules.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteRule(builder, rules[i]);
        }

        builder.Append(']');
        WriteComma(builder, comma);
    }

    private static void WriteRule(StringBuilder builder, SecretRule rule)
    {
        builder.Append('{');
        WriteString(builder, "id", rule.Id, comma: true);
        WriteString(builder, "description", rule.Description, comma: true);
        WriteString(builder, "pattern", rule.Pattern, comma: true);
        WriteString(builder, "pathPattern", rule.PathPattern, comma: true);
        WriteNumber(builder, "secretGroup", rule.SecretGroup, comma: true);
        WriteNumber(builder, "entropy", rule.Entropy, comma: true);
        WriteArray(builder, "keywords", rule.Keywords, comma: true);
        WriteArray(builder, "tags", rule.Tags, comma: true);
        WriteBoolean(builder, "skipReport", rule.SkipReport, comma: false);
        builder.Append('}');
    }

    private static void WriteFindings(StringBuilder builder, IReadOnlyList<Finding> findings, bool comma)
    {
        WritePropertyName(builder, "findings");
        builder.Append('[');
        for (int i = 0; i < findings.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteFinding(builder, findings[i]);
        }

        builder.Append(']');
        WriteComma(builder, comma);
    }

    private static void WriteFinding(StringBuilder builder, Finding finding)
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
        WriteString(builder, "author", finding.Author, comma: true);
        WriteString(builder, "email", finding.Email, comma: true);
        WriteString(builder, "date", finding.Date, comma: true);
        WriteString(builder, "message", finding.Message, comma: true);
        WriteArray(builder, "tags", finding.Tags, comma: true);
        WriteString(builder, "fingerprint", PicketFindingMetadata.CreateFingerprint(finding), comma: true);
        WriteString(builder, "validationState", PicketFindingMetadata.CreateValidationState(finding), comma: true);
        WriteString(builder, "severity", PicketFindingMetadata.Severity, comma: true);
        WriteString(builder, "confidence", PicketFindingMetadata.Confidence, comma: true);
        WriteProvenance(builder, finding, comma: true);
        WriteArray(builder, "decodePath", PicketFindingMetadata.CreateDecodePath(finding), comma: true);
        WriteString(builder, "baselineStatus", PicketFindingMetadata.BaselineStatus, comma: true);
        WriteString(builder, "ignoreReason", PicketFindingMetadata.IgnoreReason, comma: true);
        WriteEmptyArray(builder, "remediationLinks", comma: true);
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

    private static void WriteString(StringBuilder builder, string name, string value, bool comma)
    {
        WritePropertyName(builder, name);
        AppendJsonString(builder, value);
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
        builder.Append(value.ToString("G17", CultureInfo.InvariantCulture));
        WriteComma(builder, comma);
    }

    private static void WriteBoolean(StringBuilder builder, string name, bool value, bool comma)
    {
        WritePropertyName(builder, name);
        builder.Append(value ? "true" : "false");
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
        foreach (char ch in value)
        {
            switch (ch)
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
                    if (ch < ' ')
                    {
                        builder.Append("\\u");
                        builder.Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(ch);
                    }

                    break;
            }
        }

        builder.Append('"');
    }
}
