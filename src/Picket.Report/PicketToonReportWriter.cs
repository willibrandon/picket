using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes Picket-native TOON reports for compact LLM-oriented triage.
/// </summary>
public static class PicketToonReportWriter
{
    private static readonly string[] s_findingFields =
    [
        "schema",
        "ruleId",
        "description",
        "file",
        "symlinkFile",
        "startLine",
        "endLine",
        "startColumn",
        "endColumn",
        "match",
        "secret",
        "secretSha256",
        "matchSha256",
        "blobSha256",
        "decodePath",
        "line",
        "commit",
        "entropy",
        "author",
        "email",
        "date",
        "message",
        "fingerprint",
        "validationState",
        "severity",
        "confidence",
        "rulePack",
        "provider",
        "provenanceType",
        "baselineStatus",
        "ignoreReason",
        "link",
    ];

    private static readonly bool[] s_findingRawFields =
    [
        false, // schema
        false, // ruleId
        false, // description
        false, // file
        false, // symlinkFile
        true, // startLine
        true, // endLine
        true, // startColumn
        true, // endColumn
        false, // match
        false, // secret
        false, // secretSha256
        false, // matchSha256
        false, // blobSha256
        false, // decodePath
        false, // line
        false, // commit
        true, // entropy
        false, // author
        false, // email
        false, // date
        false, // message
        false, // fingerprint
        false, // validationState
        false, // severity
        false, // confidence
        false, // rulePack
        false, // provider
        false, // provenanceType
        false, // baselineStatus
        false, // ignoreReason
        false, // link
    ];

    private static readonly string[] s_ruleFields =
    [
        "id",
        "description",
        "pattern",
        "pathPattern",
        "secretGroup",
        "entropy",
        "severity",
        "confidence",
        "rulePack",
        "provider",
        "documentationUrl",
        "skipReport",
    ];

    private static readonly bool[] s_ruleRawFields =
    [
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
    ];

    private static readonly string[] s_findingTagFields = ["findingIndex", "tag"];
    private static readonly bool[] s_indexValueRawFields = [true, false];
    private static readonly string[] s_ruleKeywordFields = ["ruleIndex", "keyword"];
    private static readonly string[] s_ruleTagFields = ["ruleIndex", "tag"];

    /// <summary>
    /// Writes findings and rule metadata to a deterministic TOON report.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A TOON document without a trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        AppendLine(builder, "schema: picket.report.v1");
        AppendLine(builder, "tool:");
        AppendLine(builder, "  name: picket");
        AppendLine(builder, "summary:");
        AppendLine(builder, $"  findings: {findings.Count.ToString(CultureInfo.InvariantCulture)}");
        AppendLine(builder, $"  rules: {rules.Count.ToString(CultureInfo.InvariantCulture)}");
        Dictionary<string, SecretRule> ruleIndex = PicketFindingMetadata.CreateRuleIndex(rules);
        WriteFindings(builder, findings, ruleIndex);
        WriteFindingTags(builder, findings);
        WriteRules(builder, rules);
        WriteRuleKeywords(builder, rules);
        WriteRuleTags(builder, rules);
        return builder.ToString();
    }

    private static void WriteFindings(StringBuilder builder, IReadOnlyList<Finding> findings, IReadOnlyDictionary<string, SecretRule> ruleIndex)
    {
        if (findings.Count == 0)
        {
            AppendLine(builder, "findings: []");
            return;
        }

        WriteHeader(builder, "findings", findings.Count, s_findingFields);
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            SecretRule? rule = PicketFindingMetadata.FindRule(ruleIndex, finding);
            WriteRow(builder, 1, [
                "picket.finding.v1",
                finding.RuleID,
                finding.Description,
                finding.File,
                finding.SymlinkFile,
                finding.StartLine.ToString(CultureInfo.InvariantCulture),
                finding.EndLine.ToString(CultureInfo.InvariantCulture),
                finding.StartColumn.ToString(CultureInfo.InvariantCulture),
                finding.EndColumn.ToString(CultureInfo.InvariantCulture),
                finding.Match,
                finding.Secret,
                PicketFindingMetadata.CreateSecretSha256(finding),
                PicketFindingMetadata.CreateMatchSha256(finding),
                PicketFindingMetadata.CreateBlobSha256(finding),
                string.Join('>', PicketFindingMetadata.CreateDecodePath(finding)),
                finding.Line,
                finding.Commit,
                FormatNumber(finding.Entropy),
                finding.Author,
                finding.Email,
                finding.Date,
                finding.Message,
                PicketFindingMetadata.CreateFingerprint(finding),
                PicketFindingMetadata.CreateValidationState(finding),
                PicketFindingMetadata.CreateSeverity(rule),
                PicketFindingMetadata.CreateConfidence(rule),
                PicketFindingMetadata.CreateRulePack(rule),
                PicketFindingMetadata.CreateProvider(rule),
                PicketFindingMetadata.CreateProvenanceType(finding),
                PicketFindingMetadata.BaselineStatus,
                PicketFindingMetadata.IgnoreReason,
                finding.Link,
            ], s_findingRawFields);
        }
    }

    private static void WriteFindingTags(StringBuilder builder, IReadOnlyList<Finding> findings)
    {
        int tagCount = 0;
        for (int i = 0; i < findings.Count; i++)
        {
            tagCount += findings[i].Tags.Count;
        }

        if (tagCount == 0)
        {
            AppendLine(builder, "findingTags: []");
            return;
        }

        WriteHeader(builder, "findingTags", tagCount, s_findingTagFields);
        for (int findingIndex = 0; findingIndex < findings.Count; findingIndex++)
        {
            IReadOnlyList<string> tags = findings[findingIndex].Tags;
            for (int tagIndex = 0; tagIndex < tags.Count; tagIndex++)
            {
                WriteRow(builder, 1, [
                    findingIndex.ToString(CultureInfo.InvariantCulture),
                    tags[tagIndex],
                ], s_indexValueRawFields);
            }
        }
    }

    private static void WriteRules(StringBuilder builder, IReadOnlyList<SecretRule> rules)
    {
        if (rules.Count == 0)
        {
            AppendLine(builder, "rules: []");
            return;
        }

        WriteHeader(builder, "rules", rules.Count, s_ruleFields);
        for (int i = 0; i < rules.Count; i++)
        {
            SecretRule rule = rules[i];
            WriteRow(builder, 1, [
                rule.Id,
                rule.Description,
                rule.Pattern,
                rule.PathPattern,
                rule.SecretGroup.ToString(CultureInfo.InvariantCulture),
                FormatNumber(rule.Entropy),
                PicketFindingMetadata.CreateSeverity(rule),
                PicketFindingMetadata.CreateConfidence(rule),
                PicketFindingMetadata.CreateRulePack(rule),
                PicketFindingMetadata.CreateProvider(rule),
                PicketFindingMetadata.CreateDocumentationUrl(rule),
                rule.SkipReport ? "true" : "false",
            ], s_ruleRawFields);
        }
    }

    private static void WriteRuleKeywords(StringBuilder builder, IReadOnlyList<SecretRule> rules)
    {
        int keywordCount = 0;
        for (int i = 0; i < rules.Count; i++)
        {
            keywordCount += rules[i].Keywords.Count;
        }

        if (keywordCount == 0)
        {
            AppendLine(builder, "ruleKeywords: []");
            return;
        }

        WriteHeader(builder, "ruleKeywords", keywordCount, s_ruleKeywordFields);
        for (int ruleIndex = 0; ruleIndex < rules.Count; ruleIndex++)
        {
            IReadOnlyList<string> keywords = rules[ruleIndex].Keywords;
            for (int keywordIndex = 0; keywordIndex < keywords.Count; keywordIndex++)
            {
                WriteRow(builder, 1, [
                    ruleIndex.ToString(CultureInfo.InvariantCulture),
                    keywords[keywordIndex],
                ], s_indexValueRawFields);
            }
        }
    }

    private static void WriteRuleTags(StringBuilder builder, IReadOnlyList<SecretRule> rules)
    {
        int tagCount = 0;
        for (int i = 0; i < rules.Count; i++)
        {
            tagCount += rules[i].Tags.Count;
        }

        if (tagCount == 0)
        {
            AppendLine(builder, "ruleTags: []");
            return;
        }

        WriteHeader(builder, "ruleTags", tagCount, s_ruleTagFields);
        for (int ruleIndex = 0; ruleIndex < rules.Count; ruleIndex++)
        {
            IReadOnlyList<string> tags = rules[ruleIndex].Tags;
            for (int tagIndex = 0; tagIndex < tags.Count; tagIndex++)
            {
                WriteRow(builder, 1, [
                    ruleIndex.ToString(CultureInfo.InvariantCulture),
                    tags[tagIndex],
                ], s_indexValueRawFields);
            }
        }
    }

    private static void WriteHeader(StringBuilder builder, string name, int count, string[] fields)
    {
        AppendLine(builder, $"{name}[{count.ToString(CultureInfo.InvariantCulture)}]{{{string.Join(',', fields)}}}:");
    }

    private static void WriteRow(StringBuilder builder, int depth, string[] values, bool[] rawValues)
    {
        var row = new StringBuilder();
        row.Append(' ', depth * 2);
        for (int i = 0; i < values.Length; i++)
        {
            if (i > 0)
            {
                row.Append(',');
            }

            if (rawValues[i])
            {
                row.Append(values[i]);
            }
            else
            {
                AppendToonValue(row, values[i]);
            }
        }

        AppendLine(builder, row.ToString());
    }

    private static string FormatNumber(double value)
    {
        if (!double.IsFinite(value))
        {
            return "null";
        }

        if (value == 0)
        {
            return "0";
        }

        return value.ToString("G17", CultureInfo.InvariantCulture).Replace('E', 'e');
    }

    private static void AppendToonValue(StringBuilder builder, string value)
    {
        if (!NeedsQuotes(value))
        {
            builder.Append(value);
            return;
        }

        builder.Append('"');
        foreach (char ch in value)
        {
            switch (ch)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '"':
                    builder.Append("\\\"");
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

    private static bool NeedsQuotes(string value)
    {
        if (value.Length == 0
            || value[0] == ' '
            || value[^1] == ' '
            || value.Equals("true", StringComparison.Ordinal)
            || value.Equals("false", StringComparison.Ordinal)
            || value.Equals("null", StringComparison.Ordinal)
            || value.Equals("-", StringComparison.Ordinal)
            || value[0] == '-'
            || IsNumericLike(value))
        {
            return true;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (ch is ':' or '"' or '\\' or '[' or ']' or '{' or '}' or ','
                || ch < ' ')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNumericLike(string value)
    {
        int index = 0;
        if (value[0] == '-')
        {
            index++;
            if (index == value.Length)
            {
                return false;
            }
        }

        if (!IsAsciiDigit(value[index]))
        {
            return false;
        }

        while (index < value.Length && IsAsciiDigit(value[index]))
        {
            index++;
        }

        if (index < value.Length && value[index] == '.')
        {
            index++;
            if (index == value.Length || !IsAsciiDigit(value[index]))
            {
                return false;
            }

            while (index < value.Length && IsAsciiDigit(value[index]))
            {
                index++;
            }
        }

        if (index < value.Length && (value[index] == 'e' || value[index] == 'E'))
        {
            index++;
            if (index < value.Length && (value[index] == '+' || value[index] == '-'))
            {
                index++;
            }

            if (index == value.Length || !IsAsciiDigit(value[index]))
            {
                return false;
            }

            while (index < value.Length && IsAsciiDigit(value[index]))
            {
                index++;
            }
        }

        return index == value.Length;
    }

    private static bool IsAsciiDigit(char ch)
    {
        return ch is >= '0' and <= '9';
    }

    private static void AppendLine(StringBuilder builder, string line)
    {
        if (builder.Length > 0)
        {
            builder.Append('\n');
        }

        builder.Append(line);
    }
}
