using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes a Gitleaks-shaped SARIF 2.1.0 report.
/// </summary>
public static class GitleaksSarifReportWriter
{
    private const string SchemaUri = "https://json.schemastore.org/sarif-2.1.0.json";
    private const string ToolName = "gitleaks";
    private const string ToolSemanticVersion = "v8.0.0";
    private const string ToolInformationUri = "https://github.com/gitleaks/gitleaks";

    /// <summary>
    /// Writes findings and ordered rules to a UTF-8 SARIF JSON string.
    /// </summary>
    /// <param name="findings">The findings to report.</param>
    /// <param name="rules">The ordered rules from the active configuration.</param>
    /// <returns>The SARIF JSON report.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        builder.Append("{\n");
        WritePropertyName(builder, 1, "$schema");
        builder.Append(' ');
        AppendJsonString(builder, SchemaUri);
        builder.Append(",\n");
        WritePropertyName(builder, 1, "version");
        builder.Append(' ');
        AppendJsonString(builder, "2.1.0");
        builder.Append(",\n");
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
        WriteResults(builder, findings);
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
        WriteStringProperty(builder, 5, "semanticVersion", ToolSemanticVersion, comma: true);
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
        WritePropertyName(builder, 7, "shortDescription");
        builder.Append(" {\n");
        WriteStringProperty(builder, 8, "text", rule.Description, comma: false);
        Indent(builder, 7);
        builder.Append("}\n");
        Indent(builder, 6);
        builder.Append('}');
    }

    private static void WriteResults(StringBuilder builder, IReadOnlyList<Finding> findings)
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
            WriteResult(builder, findings[i]);
            if (i + 1 < findings.Count)
            {
                builder.Append(',');
            }

            builder.Append('\n');
        }

        Indent(builder, 3);
        builder.Append(']');
    }

    private static void WriteResult(StringBuilder builder, Finding finding)
    {
        Indent(builder, 4);
        builder.Append("{\n");
        WritePropertyName(builder, 5, "message");
        builder.Append(" {\n");
        WriteStringProperty(builder, 6, "text", GetMessageText(finding), comma: false);
        Indent(builder, 5);
        builder.Append("},\n");
        WriteStringProperty(builder, 5, "ruleId", finding.RuleID, comma: true);
        WriteLocations(builder, finding);
        builder.Append(",\n");
        WritePartialFingerprints(builder, finding);
        builder.Append(",\n");
        WriteProperties(builder, finding);
        builder.Append('\n');
        Indent(builder, 4);
        builder.Append('}');
    }

    private static void WriteLocations(StringBuilder builder, Finding finding)
    {
        WritePropertyName(builder, 5, "locations");
        builder.Append(" [\n");
        Indent(builder, 6);
        builder.Append("{\n");
        WritePropertyName(builder, 7, "physicalLocation");
        builder.Append(" {\n");
        WritePropertyName(builder, 8, "artifactLocation");
        builder.Append(" {\n");
        WriteStringProperty(builder, 9, "uri", GetLocationUri(finding), comma: false);
        Indent(builder, 8);
        builder.Append("},\n");
        WritePropertyName(builder, 8, "region");
        builder.Append(" {\n");
        WriteIntProperty(builder, 9, "startLine", finding.StartLine, comma: true);
        WriteIntProperty(builder, 9, "startColumn", finding.StartColumn, comma: true);
        WriteIntProperty(builder, 9, "endLine", finding.EndLine, comma: true);
        WriteIntProperty(builder, 9, "endColumn", finding.EndColumn, comma: true);
        WritePropertyName(builder, 9, "snippet");
        builder.Append(" {\n");
        WriteStringProperty(builder, 10, "text", finding.Secret, comma: false);
        Indent(builder, 9);
        builder.Append("}\n");
        Indent(builder, 8);
        builder.Append("}\n");
        Indent(builder, 7);
        builder.Append("}\n");
        Indent(builder, 6);
        builder.Append("}\n");
        Indent(builder, 5);
        builder.Append(']');
    }

    private static void WritePartialFingerprints(StringBuilder builder, Finding finding)
    {
        WritePropertyName(builder, 5, "partialFingerprints");
        builder.Append(" {\n");
        WriteStringProperty(builder, 6, "commitSha", finding.Commit, comma: true);
        WriteStringProperty(builder, 6, "email", finding.Email, comma: true);
        WriteStringProperty(builder, 6, "author", finding.Author, comma: true);
        WriteStringProperty(builder, 6, "date", finding.Date, comma: true);
        WriteStringProperty(builder, 6, "commitMessage", finding.Message, comma: false);
        Indent(builder, 5);
        builder.Append('}');
    }

    private static void WriteProperties(StringBuilder builder, Finding finding)
    {
        WritePropertyName(builder, 5, "properties");
        builder.Append(" {\n");
        WritePropertyName(builder, 6, "tags");
        builder.Append(" [");
        if (finding.Tags.Count == 0)
        {
            builder.Append("]\n");
        }
        else
        {
            builder.Append('\n');
            for (int i = 0; i < finding.Tags.Count; i++)
            {
                Indent(builder, 7);
                AppendJsonString(builder, finding.Tags[i]);
                if (i + 1 < finding.Tags.Count)
                {
                    builder.Append(',');
                }

                builder.Append('\n');
            }

            Indent(builder, 6);
            builder.Append("]\n");
        }

        Indent(builder, 5);
        builder.Append('}');
    }

    private static string GetMessageText(Finding finding)
    {
        if (finding.Commit.Length == 0)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{finding.RuleID} has detected secret for file {finding.File}.");
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{finding.RuleID} has detected secret for file {finding.File} at commit {finding.Commit}.");
    }

    private static string GetLocationUri(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    private static void WriteStringProperty(StringBuilder builder, int depth, string name, string value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        AppendJsonString(builder, value);
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WriteIntProperty(StringBuilder builder, int depth, string name, int value, bool comma)
    {
        WritePropertyName(builder, depth, name);
        builder.Append(' ');
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        if (comma)
        {
            builder.Append(',');
        }

        builder.Append('\n');
    }

    private static void WritePropertyName(StringBuilder builder, int depth, string name)
    {
        Indent(builder, depth);
        AppendJsonString(builder, name);
        builder.Append(':');
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
