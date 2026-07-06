using System.Globalization;
using System.Text;

namespace Picket.Analyze;

/// <summary>
/// Writes credential analysis reports.
/// </summary>
public static class CredentialAnalysisReportWriter
{
    /// <summary>
    /// Writes a compact JSON analysis report.
    /// </summary>
    /// <param name="analyses">The analysis records to write.</param>
    /// <returns>A compact JSON report.</returns>
    public static string WriteJson(IReadOnlyList<CredentialAnalysis> analyses)
    {
        ArgumentNullException.ThrowIfNull(analyses);

        var builder = new StringBuilder();
        builder.Append('{');
        WriteString(builder, "schema", "picket.analysis.report.v1", comma: true);
        WriteSummary(builder, analyses.Count, comma: true);
        WritePropertyName(builder, "analyses");
        builder.Append('[');
        for (int i = 0; i < analyses.Count; i++)
        {
            if (i != 0)
            {
                builder.Append(',');
            }

            WriteAnalysis(builder, analyses[i]);
        }

        builder.Append(']');
        builder.Append('}');
        return builder.ToString();
    }

    /// <summary>
    /// Writes JSON Lines with one analysis record per line.
    /// </summary>
    /// <param name="analyses">The analysis records to write.</param>
    /// <returns>A JSON Lines report, or an empty string when there are no records.</returns>
    public static string WriteJsonLines(IReadOnlyList<CredentialAnalysis> analyses)
    {
        ArgumentNullException.ThrowIfNull(analyses);

        if (analyses.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (int i = 0; i < analyses.Count; i++)
        {
            WriteAnalysis(builder, analyses[i]);
            builder.Append('\n');
        }

        return builder.ToString();
    }

    /// <summary>
    /// Writes a human-readable text analysis report.
    /// </summary>
    /// <param name="analyses">The analysis records to write.</param>
    /// <returns>A text report.</returns>
    public static string WriteText(IReadOnlyList<CredentialAnalysis> analyses)
    {
        ArgumentNullException.ThrowIfNull(analyses);

        var builder = new StringBuilder();
        builder.AppendLine("picket analysis");
        builder.Append("credentials: ");
        builder.AppendLine(analyses.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < analyses.Count; i++)
        {
            CredentialAnalysis analysis = analyses[i];
            builder.AppendLine();
            builder.Append(analysis.RuleId);
            builder.Append(' ');
            builder.Append(analysis.File);
            builder.Append(':');
            builder.Append(analysis.StartLine.ToString(CultureInfo.InvariantCulture));
            builder.Append(" risk=");
            builder.AppendLine(analysis.Risk);
            builder.Append("provider: ");
            builder.AppendLine(analysis.Provider);
            builder.Append("credentialType: ");
            builder.AppendLine(analysis.CredentialType);
            builder.Append("identity: ");
            builder.AppendLine(analysis.Identity);
            builder.Append("validationState: ");
            builder.AppendLine(analysis.ValidationState);
            AppendTextList(builder, "scopes", analysis.Scopes);
            AppendTextList(builder, "reachableResources", analysis.ReachableResources);
            builder.Append("summary: ");
            builder.AppendLine(analysis.RiskSummary);
            AppendTextList(builder, "recommendedActions", analysis.RecommendedActions);
            builder.Append("revocationAvailable: ");
            builder.AppendLine(analysis.RevocationAvailable ? "true" : "false");
            AppendTextList(builder, "revocationCommands", analysis.RevocationCommands);
            AppendTextList(builder, "revocationGuidance", analysis.RevocationGuidance);
            AppendTextList(builder, "evidence", analysis.Evidence);
        }

        return builder.ToString();
    }

    private static void WriteSummary(StringBuilder builder, int count, bool comma)
    {
        WritePropertyName(builder, "summary");
        builder.Append('{');
        WriteNumber(builder, "credentials", count, comma: false);
        builder.Append('}');
        WriteComma(builder, comma);
    }

    private static void WriteAnalysis(StringBuilder builder, CredentialAnalysis analysis)
    {
        builder.Append('{');
        WriteString(builder, "schema", analysis.Schema, comma: true);
        WriteString(builder, "ruleId", analysis.RuleId, comma: true);
        WriteString(builder, "provider", analysis.Provider, comma: true);
        WriteString(builder, "credentialType", analysis.CredentialType, comma: true);
        WriteString(builder, "file", analysis.File, comma: true);
        WriteNumber(builder, "startLine", analysis.StartLine, comma: true);
        WriteNumber(builder, "startColumn", analysis.StartColumn, comma: true);
        WriteString(builder, "fingerprint", analysis.Fingerprint, comma: true);
        WriteString(builder, "secretSha256", analysis.SecretSha256, comma: true);
        WriteString(builder, "validationState", analysis.ValidationState, comma: true);
        WriteString(builder, "risk", analysis.Risk, comma: true);
        WriteString(builder, "identity", analysis.Identity, comma: true);
        WriteArray(builder, "scopes", analysis.Scopes, comma: true);
        WriteArray(builder, "reachableResources", analysis.ReachableResources, comma: true);
        WriteString(builder, "riskSummary", analysis.RiskSummary, comma: true);
        WriteArray(builder, "recommendedActions", analysis.RecommendedActions, comma: true);
        WriteBoolean(builder, "revocationAvailable", analysis.RevocationAvailable, comma: true);
        WriteArray(builder, "revocationCommands", analysis.RevocationCommands, comma: true);
        WriteArray(builder, "revocationGuidance", analysis.RevocationGuidance, comma: true);
        WriteArray(builder, "evidence", analysis.Evidence, comma: false);
        builder.Append('}');
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
            if (i != 0)
            {
                builder.Append(',');
            }

            AppendJsonString(builder, values[i]);
        }

        builder.Append(']');
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

    private static void AppendTextList(StringBuilder builder, string name, IReadOnlyList<string> values)
    {
        builder.Append(name);
        builder.AppendLine(":");
        for (int i = 0; i < values.Count; i++)
        {
            builder.Append("  - ");
            builder.AppendLine(values[i]);
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
