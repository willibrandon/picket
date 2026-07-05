using System.Globalization;
using System.Text;
using Picket.Engine;

namespace Picket.Report;

/// <summary>
/// Writes a Gitleaks-shaped JSON report with deterministic field ordering.
/// </summary>
public static class GitleaksJsonReportWriter
{
    /// <summary>
    /// Writes findings to a UTF-8 JSON string.
    /// </summary>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return "[]\n";
        }

        var builder = new StringBuilder();
        builder.Append("[\n");
        for (int i = 0; i < findings.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(",\n");
            }

            WriteFinding(builder, findings[i]);
        }

        builder.Append('\n');
        builder.Append("]\n");
        return builder.ToString();
    }

    private static void WriteFinding(StringBuilder builder, Finding finding)
    {
        builder.Append(" {\n");
        WriteString(builder, "RuleID", finding.RuleID, comma: true);
        WriteString(builder, "Description", finding.Description, comma: true);
        WriteNumber(builder, "StartLine", finding.StartLine, comma: true);
        WriteNumber(builder, "EndLine", finding.EndLine, comma: true);
        WriteNumber(builder, "StartColumn", finding.StartColumn, comma: true);
        WriteNumber(builder, "EndColumn", finding.EndColumn, comma: true);
        WriteString(builder, "Match", finding.Match, comma: true);
        WriteString(builder, "Secret", finding.Secret, comma: true);
        WriteString(builder, "File", finding.File, comma: true);
        WriteString(builder, "SymlinkFile", finding.SymlinkFile, comma: true);
        WriteString(builder, "Commit", finding.Commit, comma: true);
        if (finding.Link.Length != 0)
        {
            WriteString(builder, "Link", finding.Link, comma: true);
        }

        WriteNumber(builder, "Entropy", finding.Entropy, comma: true);
        WriteString(builder, "Author", finding.Author, comma: true);
        WriteString(builder, "Email", finding.Email, comma: true);
        WriteString(builder, "Date", finding.Date, comma: true);
        WriteString(builder, "Message", finding.Message, comma: true);
        WriteArray(builder, "Tags", finding.Tags, comma: true);
        WriteString(builder, "Fingerprint", finding.Fingerprint, comma: false);
        builder.Append(" }");
    }

    private static void WriteString(StringBuilder builder, string name, string value, bool comma)
    {
        builder.Append("  \"");
        builder.Append(name);
        builder.Append("\": ");
        AppendJsonString(builder, value);
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteNumber(StringBuilder builder, string name, int value, bool comma)
    {
        builder.Append("  \"");
        builder.Append(name);
        builder.Append("\": ");
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteNumber(StringBuilder builder, string name, double value, bool comma)
    {
        builder.Append("  \"");
        builder.Append(name);
        builder.Append("\": ");
        builder.Append(((float)value).ToString("G", CultureInfo.InvariantCulture));
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteArray(StringBuilder builder, string name, IReadOnlyList<string> values, bool comma)
    {
        builder.Append("  \"");
        builder.Append(name);
        builder.Append("\": ");
        if (values.Count == 0)
        {
            builder.Append("[]");
            if (comma)
            {
                builder.Append(',');
            }

            builder.Append('\n');
            return;
        }

        builder.Append("[\n");
        for (int i = 0; i < values.Count; i++)
        {
            builder.Append("   ");
            AppendJsonString(builder, values[i]);
            if (i + 1 < values.Count)
            {
                builder.Append(',');
            }

            builder.Append('\n');
        }

        builder.Append("  ]");
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
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
