using Picket.Engine;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes a Gitleaks-shaped JUnit XML report.
/// </summary>
public static class GitleaksJunitReportWriter
{
    /// <summary>
    /// Writes findings to a UTF-8 JUnit XML string.
    /// </summary>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var builder = new StringBuilder();
        builder.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        builder.Append("<testsuites>\n");
        builder.Append('\t');
        builder.Append("<testsuite failures=\"");
        builder.Append(findings.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append("\" name=\"gitleaks\" tests=\"");
        builder.Append(findings.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append("\" time=\"\">");
        if (findings.Count == 0)
        {
            builder.Append("</testsuite>\n");
            builder.Append("</testsuites>");
            return builder.ToString();
        }

        builder.Append('\n');
        foreach (Finding finding in findings)
        {
            string message = GetMessage(finding);
            builder.Append("\t\t<testcase classname=\"");
            AppendXmlAttribute(builder, finding.Description);
            builder.Append("\" file=\"");
            AppendXmlAttribute(builder, finding.File);
            builder.Append("\" name=\"");
            AppendXmlAttribute(builder, message);
            builder.Append("\" time=\"\">\n");
            builder.Append("\t\t\t<failure message=\"");
            AppendXmlAttribute(builder, message);
            builder.Append("\" type=\"");
            AppendXmlAttribute(builder, finding.Description);
            builder.Append("\">");
            AppendXmlCharacterData(builder, WriteJsonFinding(finding));
            builder.Append("</failure>\n");
            builder.Append("\t\t</testcase>\n");
        }

        builder.Append("\t</testsuite>\n");
        builder.Append("</testsuites>");
        return builder.ToString();
    }

    private static string GetMessage(Finding finding)
    {
        if (finding.Commit.Length == 0)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{finding.RuleID} has detected a secret in file {finding.File}, line {finding.StartLine}.");
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{finding.RuleID} has detected a secret in file {finding.File}, line {finding.StartLine}, at commit {finding.Commit}.");
    }

    private static string WriteJsonFinding(Finding finding)
    {
        var builder = new StringBuilder();
        builder.Append("{\n");
        WriteJsonString(builder, "RuleID", finding.RuleID, comma: true);
        WriteJsonString(builder, "Description", finding.Description, comma: true);
        WriteJsonNumber(builder, "StartLine", finding.StartLine, comma: true);
        WriteJsonNumber(builder, "EndLine", finding.EndLine, comma: true);
        WriteJsonNumber(builder, "StartColumn", finding.StartColumn, comma: true);
        WriteJsonNumber(builder, "EndColumn", finding.EndColumn, comma: true);
        WriteJsonString(builder, "Match", finding.Match, comma: true);
        WriteJsonString(builder, "Secret", finding.Secret, comma: true);
        WriteJsonString(builder, "File", finding.File, comma: true);
        WriteJsonString(builder, "SymlinkFile", finding.SymlinkFile, comma: true);
        WriteJsonString(builder, "Commit", finding.Commit, comma: true);
        if (finding.Link.Length != 0)
        {
            WriteJsonString(builder, "Link", finding.Link, comma: true);
        }

        WriteJsonNumber(builder, "Entropy", finding.Entropy, comma: true);
        WriteJsonString(builder, "Author", finding.Author, comma: true);
        WriteJsonString(builder, "Email", finding.Email, comma: true);
        WriteJsonString(builder, "Date", finding.Date, comma: true);
        WriteJsonString(builder, "Message", finding.Message, comma: true);
        WriteJsonArray(builder, "Tags", finding.Tags, comma: true);
        WriteJsonString(builder, "Fingerprint", finding.Fingerprint, comma: false);
        builder.Append('}');
        return builder.ToString();
    }

    private static void WriteJsonString(StringBuilder builder, string name, string value, bool comma)
    {
        builder.Append('\t');
        AppendJsonString(builder, name);
        builder.Append(": ");
        AppendJsonString(builder, value);
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteJsonNumber(StringBuilder builder, string name, int value, bool comma)
    {
        builder.Append('\t');
        AppendJsonString(builder, name);
        builder.Append(": ");
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteJsonNumber(StringBuilder builder, string name, double value, bool comma)
    {
        builder.Append('\t');
        AppendJsonString(builder, name);
        builder.Append(": ");
        builder.Append(ReportNumberFormatter.FormatGitleaksFloat(value));
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteJsonArray(StringBuilder builder, string name, IReadOnlyList<string> values, bool comma)
    {
        builder.Append('\t');
        AppendJsonString(builder, name);
        builder.Append(": ");
        if (values.Count == 0)
        {
            builder.Append("[]");
        }
        else
        {
            builder.Append("[\n");
            for (int i = 0; i < values.Count; i++)
            {
                builder.Append("\t\t");
                AppendJsonString(builder, values[i]);
                if (i + 1 < values.Count)
                {
                    builder.Append(',');
                }

                builder.Append('\n');
            }

            builder.Append('\t');
            builder.Append(']');
        }

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

    private static void AppendXmlAttribute(StringBuilder builder, string value)
    {
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    builder.Append("&#34;");
                    break;
                case '\'':
                    builder.Append("&#39;");
                    break;
                case '&':
                    builder.Append("&amp;");
                    break;
                case '<':
                    builder.Append("&lt;");
                    break;
                case '>':
                    builder.Append("&gt;");
                    break;
                case '\n':
                    builder.Append("&#xA;");
                    break;
                case '\r':
                    builder.Append("&#xD;");
                    break;
                case '\t':
                    builder.Append("&#x9;");
                    break;
                default:
                    AppendXmlRune(builder, rune);
                    break;
            }
        }
    }

    private static void AppendXmlCharacterData(StringBuilder builder, string value)
    {
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    builder.Append("&#34;");
                    break;
                case '\'':
                    builder.Append("&#39;");
                    break;
                case '&':
                    builder.Append("&amp;");
                    break;
                case '<':
                    builder.Append("&lt;");
                    break;
                case '>':
                    builder.Append("&gt;");
                    break;
                case '\n':
                    builder.Append("&#xA;");
                    break;
                case '\r':
                    builder.Append("&#xD;");
                    break;
                case '\t':
                    builder.Append("&#x9;");
                    break;
                default:
                    AppendXmlRune(builder, rune);
                    break;
            }
        }
    }

    private static void AppendXmlRune(StringBuilder builder, Rune rune)
    {
        if (IsInvalidXmlCharacter(rune.Value))
        {
            builder.Append('\uFFFD');
            return;
        }

        builder.Append(rune.ToString());
    }

    private static bool IsInvalidXmlCharacter(int value)
    {
        return value < 0x20
            || value is > 0xD7FF and < 0xE000
            || value is 0xFFFE or 0xFFFF
            || value > 0x10FFFF;
    }
}
