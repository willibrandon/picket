using System.Globalization;
using System.Text;
using Picket.Rules;

namespace Picket.Compat;

/// <summary>
/// Writes resolved Gitleaks-compatible rule sets as deterministic TOML.
/// </summary>
public static class GitleaksConfigWriter
{
    /// <summary>
    /// Writes a resolved rule set as deterministic TOML.
    /// </summary>
    /// <param name="ruleSet">The rule set to write.</param>
    /// <returns>A deterministic TOML representation of the rule set.</returns>
    public static string Write(RuleSet ruleSet)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);

        var builder = new StringBuilder();
        for (int i = 0; i < ruleSet.Allowlists.Count; i++)
        {
            AppendSeparator(builder);
            AppendAllowlist(builder, "[[allowlists]]", ruleSet.Allowlists[i]);
        }

        for (int i = 0; i < ruleSet.Rules.Count; i++)
        {
            SecretRule rule = ruleSet.Rules[i];
            AppendSeparator(builder);
            builder.AppendLine("[[rules]]");
            AppendString(builder, "id", rule.Id);
            if (rule.Description.Length != 0)
            {
                AppendString(builder, "description", rule.Description);
            }

            if (rule.Pattern.Length != 0)
            {
                AppendString(builder, "regex", rule.Pattern);
            }

            if (rule.PathPattern.Length != 0)
            {
                AppendString(builder, "path", rule.PathPattern);
            }

            if (rule.SecretGroup != 0)
            {
                AppendNumber(builder, "secretGroup", rule.SecretGroup);
            }

            if (rule.Entropy != 0)
            {
                AppendNumber(builder, "entropy", rule.Entropy);
            }

            AppendStringArray(builder, "keywords", rule.Keywords);
            AppendStringArray(builder, "tags", rule.Tags);
            if (rule.SkipReport)
            {
                builder.AppendLine("skipReport = true");
            }

            for (int requiredIndex = 0; requiredIndex < rule.RequiredRules.Count; requiredIndex++)
            {
                SecretRequiredRule requiredRule = rule.RequiredRules[requiredIndex];
                builder.AppendLine();
                builder.AppendLine("[[rules.required]]");
                AppendString(builder, "id", requiredRule.Id);
                if (requiredRule.WithinLines.HasValue)
                {
                    AppendNumber(builder, "withinLines", requiredRule.WithinLines.Value);
                }

                if (requiredRule.WithinColumns.HasValue)
                {
                    AppendNumber(builder, "withinColumns", requiredRule.WithinColumns.Value);
                }
            }

            for (int allowlistIndex = 0; allowlistIndex < rule.Allowlists.Count; allowlistIndex++)
            {
                builder.AppendLine();
                AppendAllowlist(builder, "[[rules.allowlists]]", rule.Allowlists[allowlistIndex]);
            }
        }

        return builder.ToString();
    }

    private static void AppendAllowlist(StringBuilder builder, string header, SecretAllowlist allowlist)
    {
        builder.AppendLine(header);
        if (allowlist.Description.Length != 0)
        {
            AppendString(builder, "description", allowlist.Description);
        }

        AppendString(builder, "condition", allowlist.Condition == AllowlistCondition.And ? "AND" : "OR");
        AppendStringArray(builder, "commits", allowlist.Commits);
        AppendStringArray(builder, "paths", allowlist.PathPatterns);
        AppendString(builder, "regexTarget", GetRegexTarget(allowlist.RegexTarget));
        AppendStringArray(builder, "regexes", allowlist.RegexPatterns);
        AppendStringArray(builder, "stopwords", allowlist.StopWords);
    }

    private static string GetRegexTarget(AllowlistRegexTarget target)
    {
        return target switch
        {
            AllowlistRegexTarget.Match => "match",
            AllowlistRegexTarget.Line => "line",
            _ => "secret",
        };
    }

    private static void AppendSeparator(StringBuilder builder)
    {
        if (builder.Length != 0)
        {
            builder.AppendLine();
        }
    }

    private static void AppendString(StringBuilder builder, string name, string value)
    {
        builder.Append(name);
        builder.Append(" = ");
        AppendQuotedString(builder, value);
        builder.AppendLine();
    }

    private static void AppendNumber(StringBuilder builder, string name, int value)
    {
        builder.Append(name);
        builder.Append(" = ");
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        builder.AppendLine();
    }

    private static void AppendNumber(StringBuilder builder, string name, double value)
    {
        builder.Append(name);
        builder.Append(" = ");
        builder.Append(value.ToString("G17", CultureInfo.InvariantCulture));
        builder.AppendLine();
    }

    private static void AppendStringArray(StringBuilder builder, string name, IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return;
        }

        builder.Append(name);
        builder.Append(" = [");
        for (int i = 0; i < values.Count; i++)
        {
            if (i != 0)
            {
                builder.Append(", ");
            }

            AppendQuotedString(builder, values[i]);
        }

        builder.AppendLine("]");
    }

    private static void AppendQuotedString(StringBuilder builder, string value)
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
                case '\t':
                    builder.Append("\\t");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\r':
                    builder.Append("\\r");
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
