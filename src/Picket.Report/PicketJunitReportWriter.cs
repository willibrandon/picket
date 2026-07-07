using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native JUnit XML reports.
/// </summary>
public static class PicketJunitReportWriter
{
    /// <summary>
    /// Writes findings to a deterministic UTF-8 JUnit XML string.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <returns>A JUnit XML report with Picket-native finding metadata.</returns>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        return Write(findings, []);
    }

    /// <summary>
    /// Writes findings to a deterministic UTF-8 JUnit XML string with rule-derived metadata.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A JUnit XML report with Picket-native finding metadata.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        builder.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        builder.Append("<testsuites>\n");
        builder.Append('\t');
        builder.Append("<testsuite failures=\"");
        builder.Append(findings.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append("\" name=\"picket\" tests=\"");
        builder.Append(findings.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append("\" time=\"\">\n");
        WriteProperties(builder);
        for (int i = 0; i < findings.Count; i++)
        {
            WriteTestCase(builder, findings[i], rules);
        }

        builder.Append("\t</testsuite>\n");
        builder.Append("</testsuites>");
        return builder.ToString();
    }

    private static void WriteProperties(StringBuilder builder)
    {
        builder.Append("\t\t<properties>\n");
        builder.Append("\t\t\t<property name=\"schema\" value=\"picket.junit.v1\"></property>\n");
        builder.Append("\t\t\t<property name=\"tool\" value=\"picket\"></property>\n");
        builder.Append("\t\t</properties>\n");
    }

    private static void WriteTestCase(StringBuilder builder, Finding finding, IReadOnlyList<SecretRule> rules)
    {
        string message = CreateMessage(finding);
        builder.Append("\t\t<testcase classname=\"");
        AppendXmlAttribute(builder, finding.RuleID);
        builder.Append("\" file=\"");
        AppendXmlAttribute(builder, CreateLocationPath(finding));
        builder.Append("\" name=\"");
        AppendXmlAttribute(builder, message);
        builder.Append("\" time=\"\">\n");
        builder.Append("\t\t\t<failure message=\"");
        AppendXmlAttribute(builder, message);
        builder.Append("\" type=\"picket.finding.v1\">");
        AppendXmlCharacterData(builder, WriteJsonFinding(finding, rules));
        builder.Append("</failure>\n");
        builder.Append("\t\t</testcase>\n");
    }

    private static string CreateMessage(Finding finding)
    {
        string description = finding.Description.Length == 0 ? finding.RuleID : $"{finding.RuleID}: {finding.Description}";
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{description} detected a secret in {CreateLocationPath(finding)} on line {finding.StartLine}.");
    }

    private static string CreateLocationPath(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    private static string WriteJsonFinding(Finding finding, IReadOnlyList<SecretRule> rules)
    {
        string json = PicketJsonlReportWriter.Write([finding], rules);
        return json.Length > 0 && json[^1] == '\n' ? json[..^1] : json;
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
            builder.Append("&#xFFFD;");
            return;
        }

        builder.Append(rune.ToString());
    }

    private static bool IsInvalidXmlCharacter(int value)
    {
        return value < 0x20
            || value is > 0xD7FF and < 0xE000
            || value > 0x10FFFF;
    }
}
