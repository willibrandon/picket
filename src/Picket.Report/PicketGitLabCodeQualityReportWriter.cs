using System.Globalization;
using System.Text;
using Picket.Engine;

namespace Picket.Report;

/// <summary>
/// Writes Picket findings as a GitLab Code Quality report.
/// </summary>
public static class PicketGitLabCodeQualityReportWriter
{
    /// <summary>
    /// Writes findings to GitLab's Code Quality JSON array format.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <returns>A GitLab Code Quality report with a trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var builder = new StringBuilder();
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
        builder.Append('\n');
        return builder.ToString();
    }

    private static void WriteFinding(StringBuilder builder, Finding finding)
    {
        builder.Append('{');
        WriteString(builder, "description", CreateDescription(finding), comma: true);
        WriteString(builder, "check_name", finding.RuleID, comma: true);
        WriteString(builder, "fingerprint", CreateFingerprint(finding), comma: true);
        WriteString(builder, "severity", "critical", comma: true);
        WriteLocation(builder, finding, comma: false);
        builder.Append('}');
    }

    private static string CreateDescription(Finding finding)
    {
        return finding.Description.Length == 0
            ? $"{finding.RuleID} detected a secret in {CreateLocationPath(finding)} on line {finding.StartLine}."
            : $"{finding.RuleID}: {finding.Description}";
    }

    private static string CreateFingerprint(Finding finding)
    {
        return finding.Fingerprint.Length == 0
            ? string.Create(
                CultureInfo.InvariantCulture,
                $"{CreateLocationPath(finding)}:{finding.RuleID}:{finding.StartLine}:{finding.StartColumn}")
            : finding.Fingerprint;
    }

    private static string CreateLocationPath(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    private static void WriteLocation(StringBuilder builder, Finding finding, bool comma)
    {
        WritePropertyName(builder, "location");
        builder.Append('{');
        WriteString(builder, "path", CreateLocationPath(finding), comma: true);
        WritePropertyName(builder, "lines");
        builder.Append('{');
        WriteNumber(builder, "begin", finding.StartLine, comma: false);
        builder.Append('}');
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
