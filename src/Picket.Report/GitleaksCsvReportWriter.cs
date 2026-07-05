using Picket.Engine;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes a Gitleaks-shaped CSV report with deterministic column ordering.
/// </summary>
public static class GitleaksCsvReportWriter
{
    private static readonly string[] s_columns =
    [
        "RuleID",
        "Commit",
        "File",
        "SymlinkFile",
        "Secret",
        "Match",
        "StartLine",
        "EndLine",
        "StartColumn",
        "EndColumn",
        "Author",
        "Message",
        "Date",
        "Email",
        "Fingerprint",
        "Tags",
    ];

    /// <summary>
    /// Writes findings to a UTF-8 CSV string.
    /// </summary>
    public static string Write(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        WriteRow(builder, s_columns);
        foreach (Finding finding in findings)
        {
            WriteRow(builder, [
                finding.RuleID,
                finding.Commit,
                finding.File,
                finding.SymlinkFile,
                finding.Secret,
                finding.Match,
                finding.StartLine.ToString(CultureInfo.InvariantCulture),
                finding.EndLine.ToString(CultureInfo.InvariantCulture),
                finding.StartColumn.ToString(CultureInfo.InvariantCulture),
                finding.EndColumn.ToString(CultureInfo.InvariantCulture),
                finding.Author,
                finding.Message,
                finding.Date,
                finding.Email,
                finding.Fingerprint,
                string.Join(' ', finding.Tags),
            ]);
        }

        return builder.ToString();
    }

    private static void WriteRow(StringBuilder builder, IReadOnlyList<string> fields)
    {
        for (int i = 0; i < fields.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            AppendField(builder, fields[i]);
        }

        builder.Append('\n');
    }

    private static void AppendField(StringBuilder builder, string value)
    {
        if (!NeedsQuotes(value))
        {
            builder.Append(value);
            return;
        }

        builder.Append('"');
        foreach (char c in value)
        {
            if (c == '"')
            {
                builder.Append("\"\"");
            }
            else
            {
                builder.Append(c);
            }
        }

        builder.Append('"');
    }

    private static bool NeedsQuotes(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        char first = value[0];
        if (first is ' ' or '\t')
        {
            return true;
        }

        return value.Contains(',')
            || value.Contains('"')
            || value.Contains('\r')
            || value.Contains('\n');
    }
}
