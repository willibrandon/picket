using System.Globalization;
using System.Text;
using Picket.Engine;

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
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (Finding finding in findings)
        {
            WriteFinding(builder, finding);
            builder.Append('\n');
        }

        return builder.ToString();
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
        WriteString(builder, "line", finding.Line, comma: true);
        WriteString(builder, "commit", finding.Commit, comma: true);
        WriteNumber(builder, "entropy", finding.Entropy, comma: true);
        WriteString(builder, "author", finding.Author, comma: true);
        WriteString(builder, "email", finding.Email, comma: true);
        WriteString(builder, "date", finding.Date, comma: true);
        WriteString(builder, "message", finding.Message, comma: true);
        WriteArray(builder, "tags", finding.Tags, comma: true);
        WriteString(builder, "fingerprint", finding.Fingerprint, comma: true);
        WriteString(builder, "validationState", PicketFindingMetadata.CreateValidationState(finding), comma: true);
        WriteString(builder, "severity", PicketFindingMetadata.Severity, comma: true);
        WriteString(builder, "confidence", PicketFindingMetadata.Confidence, comma: true);
        WriteProvenance(builder, finding, comma: true);
        WriteEmptyArray(builder, "decodePath", comma: true);
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
