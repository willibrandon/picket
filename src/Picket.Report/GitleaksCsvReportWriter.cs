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
        bool includeLink = findings[0].Link.Length != 0;
        if (includeLink)
        {
            WriteRow(builder, [.. s_columns, "Link"]);
        }
        else
        {
            WriteRow(builder, s_columns);
        }

        foreach (Finding finding in findings)
        {
            string[] row =
            [
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
            ];
            if (includeLink)
            {
                WriteRow(builder, [.. row, finding.Link]);
            }
            else
            {
                WriteRow(builder, row);
            }
        }

        return builder.ToString();
    }

    private static void WriteRow(StringBuilder builder, string[] fields)
    {
        for (int i = 0; i < fields.Length; i++)
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

        if (value.Equals("\\.", StringComparison.Ordinal) || char.IsWhiteSpace(value, 0))
        {
            return true;
        }

        return value.Contains(',')
            || value.Contains('"')
            || value.Contains('\r')
            || value.Contains('\n');
    }
}
