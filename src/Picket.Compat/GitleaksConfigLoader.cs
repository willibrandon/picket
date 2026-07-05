using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Compat;

/// <summary>
/// Loads the Gitleaks-compatible rule subset currently implemented by Picket.
/// </summary>
public static class GitleaksConfigLoader
{
    private const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
    private const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
    private const string GitleaksConfigFileName = ".gitleaks.toml";

    /// <summary>
    /// Loads rules using Gitleaks-compatible config precedence.
    /// </summary>
    /// <param name="configPath">The explicit config path supplied by <c>--config</c> or <c>-c</c>.</param>
    /// <param name="source">The scan source used to discover a target-local <c>.gitleaks.toml</c>.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet LoadRuleSet(string? configPath, string source)
    {
        if (!string.IsNullOrWhiteSpace(configPath))
        {
            return LoadFile(configPath);
        }

        string? environmentPath = Environment.GetEnvironmentVariable(GitleaksConfigEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentPath))
        {
            return LoadFile(environmentPath);
        }

        string? environmentToml = Environment.GetEnvironmentVariable(GitleaksConfigTomlEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentToml))
        {
            return FromToml(environmentToml, GitleaksConfigTomlEnvironmentVariable);
        }

        if (Directory.Exists(source))
        {
            string sourceConfigPath = Path.Combine(source, GitleaksConfigFileName);
            if (File.Exists(sourceConfigPath))
            {
                return LoadFile(sourceConfigPath);
            }
        }

        return EmbeddedGitleaksRules.Bootstrap;
    }

    /// <summary>
    /// Loads rules from a Gitleaks TOML file.
    /// </summary>
    /// <param name="path">The TOML file path.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet LoadFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromToml(File.ReadAllText(path), path);
    }

    /// <summary>
    /// Loads rules from Gitleaks TOML content.
    /// </summary>
    /// <param name="toml">The TOML content.</param>
    /// <param name="sourceName">The source name used in diagnostics.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet FromToml(string toml, string sourceName)
    {
        ArgumentNullException.ThrowIfNull(toml);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);

        var rules = new List<SecretRule>();
        var globalAllowlists = new List<SecretAllowlist>();
        var targetedGlobalAllowlists = new Dictionary<string, List<SecretAllowlist>>(StringComparer.Ordinal);
        var ruleAllowlists = new List<SecretAllowlist>();
        var ruleRequiredRules = new List<SecretRequiredRule>();
        string section = string.Empty;
        string allowlistScope = string.Empty;
        bool hasRule = false;
        bool hasAllowlist = false;
        bool hasRequiredRule = false;
        string id = string.Empty;
        string description = string.Empty;
        string pattern = string.Empty;
        string pathPattern = string.Empty;
        int secretGroup = 0;
        double entropy = 0;
        bool skipReport = false;
        IReadOnlyList<string> keywords = [];
        IReadOnlyList<string> tags = [];
        string allowlistDescription = string.Empty;
        AllowlistCondition allowlistCondition = AllowlistCondition.Or;
        List<string> allowlistCommits = [];
        List<string> allowlistPaths = [];
        AllowlistRegexTarget allowlistRegexTarget = AllowlistRegexTarget.Secret;
        List<string> allowlistRegexes = [];
        List<string> allowlistStopWords = [];
        List<string> allowlistTargetRules = [];
        string requiredRuleId = string.Empty;
        int? requiredWithinLines = null;
        int? requiredWithinColumns = null;
        string[] lines = toml.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

        for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            string line = StripComment(lines[lineIndex]).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("[[", StringComparison.Ordinal) && line.EndsWith("]]", StringComparison.Ordinal))
            {
                string table = line[2..^2].Trim();
                if (table.Equals("rules", StringComparison.Ordinal))
                {
                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    AddCurrentRule();
                    section = "rules";
                    hasRule = true;
                    id = string.Empty;
                    description = string.Empty;
                    pattern = string.Empty;
                    pathPattern = string.Empty;
                    secretGroup = 0;
                    entropy = 0;
                    skipReport = false;
                    keywords = [];
                    tags = [];
                    continue;
                }

                if (table.Equals("rules.allowlists", StringComparison.Ordinal))
                {
                    if (!hasRule)
                    {
                        throw new InvalidDataException($"{sourceName}: [[rules.allowlists]] must follow a [[rules]] entry");
                    }

                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    StartAllowlist("rule");
                    continue;
                }

                if (table.Equals("rules.required", StringComparison.Ordinal))
                {
                    if (!hasRule)
                    {
                        throw new InvalidDataException($"{sourceName}: [[rules.required]] must follow a [[rules]] entry");
                    }

                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    StartRequiredRule();
                    continue;
                }

                if (table.Equals("allowlists", StringComparison.Ordinal))
                {
                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    AddCurrentRule();
                    StartAllowlist("global");
                    continue;
                }

                ThrowUnsupportedTable(table, sourceName);
                section = table;
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                string table = line[1..^1].Trim();
                if (table.Equals("rules.allowlist", StringComparison.Ordinal))
                {
                    if (!hasRule)
                    {
                        throw new InvalidDataException($"{sourceName}: [rules.allowlist] must follow a [[rules]] entry");
                    }

                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    StartAllowlist("rule");
                    continue;
                }

                if (table.Equals("allowlist", StringComparison.Ordinal))
                {
                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    AddCurrentRule();
                    StartAllowlist("global");
                    continue;
                }

                ThrowUnsupportedTable(table, sourceName);
                section = table;
                continue;
            }

            if (!TrySplitAssignment(line, out string key, out string value))
            {
                throw new InvalidDataException($"{sourceName}: invalid TOML assignment on line {lineIndex + 1}");
            }

            if (ValueContinues(value))
            {
                value = ReadMultilineValue(lines, ref lineIndex, value);
            }

            if (section.Equals("extend", StringComparison.Ordinal))
            {
                ThrowUnsupported(sourceName, "extend blocks");
            }

            if (section.Equals("allowlist", StringComparison.Ordinal))
            {
                switch (key)
                {
                    case "description":
                        allowlistDescription = ParseString(value, sourceName, key);
                        break;
                    case "condition":
                        allowlistCondition = ParseAllowlistCondition(value, sourceName, key);
                        break;
                    case "commits":
                        allowlistCommits = ParseStringArray(value, sourceName, key);
                        break;
                    case "paths":
                        allowlistPaths = ParseStringArray(value, sourceName, key);
                        break;
                    case "regexTarget":
                        allowlistRegexTarget = ParseAllowlistRegexTarget(value, sourceName, key);
                        break;
                    case "regexes":
                        allowlistRegexes = ParseStringArray(value, sourceName, key);
                        break;
                    case "stopwords":
                        allowlistStopWords = ParseStringArray(value, sourceName, key);
                        break;
                    case "targetRules":
                        if (!allowlistScope.Equals("global", StringComparison.Ordinal))
                        {
                            throw new InvalidDataException($"{sourceName}: 'targetRules' is only valid on global allowlists");
                        }

                        allowlistTargetRules = ParseStringArray(value, sourceName, key);
                        break;
                }

                continue;
            }

            if (section.Equals("required", StringComparison.Ordinal))
            {
                switch (key)
                {
                    case "id":
                        requiredRuleId = ParseString(value, sourceName, key);
                        break;
                    case "withinLines":
                        requiredWithinLines = ParseNonNegativeInt(value, sourceName, key);
                        break;
                    case "withinColumns":
                        requiredWithinColumns = ParseNonNegativeInt(value, sourceName, key);
                        break;
                }

                continue;
            }

            if (!section.Equals("rules", StringComparison.Ordinal))
            {
                continue;
            }

            switch (key)
            {
                case "id":
                    id = ParseString(value, sourceName, key);
                    break;
                case "description":
                    description = ParseString(value, sourceName, key);
                    break;
                case "regex":
                    pattern = ParseString(value, sourceName, key);
                    break;
                case "path":
                    pathPattern = ParseString(value, sourceName, key);
                    break;
                case "secretGroup":
                    secretGroup = ParseNonNegativeInt(value, sourceName, key);
                    break;
                case "entropy":
                    entropy = ParseNonNegativeDouble(value, sourceName, key);
                    break;
                case "keywords":
                    keywords = ParseStringArray(value, sourceName, key);
                    break;
                case "tags":
                    tags = ParseStringArray(value, sourceName, key);
                    break;
                case "skipReport":
                    skipReport = ParseBoolean(value, sourceName, key);
                    break;
            }
        }

        AddCurrentAllowlist();
        AddCurrentRequiredRule();
        AddCurrentRule();
        ApplyTargetedGlobalAllowlists();
        ValidateRequiredRules();
        if (rules.Count == 0)
        {
            throw new InvalidDataException($"{sourceName}: no [[rules]] entries were found");
        }

        return new RuleSet(rules, globalAllowlists);

        void StartAllowlist(string scope)
        {
            section = "allowlist";
            allowlistScope = scope;
            hasAllowlist = true;
            allowlistDescription = string.Empty;
            allowlistCondition = AllowlistCondition.Or;
            allowlistCommits = [];
            allowlistPaths = [];
            allowlistRegexTarget = AllowlistRegexTarget.Secret;
            allowlistRegexes = [];
            allowlistStopWords = [];
            allowlistTargetRules = [];
        }

        void StartRequiredRule()
        {
            section = "required";
            hasRequiredRule = true;
            requiredRuleId = string.Empty;
            requiredWithinLines = null;
            requiredWithinColumns = null;
        }

        void AddCurrentAllowlist()
        {
            if (!hasAllowlist)
            {
                return;
            }

            SecretAllowlist allowlist;
            try
            {
                allowlist = SecretAllowlist.Create(
                    allowlistDescription,
                    allowlistCondition,
                    allowlistCommits,
                    allowlistPaths,
                    allowlistRegexTarget,
                    allowlistRegexes,
                    allowlistStopWords);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException($"{sourceName}: allowlist must contain at least one check for: commits, paths, regexes, or stopwords", exception);
            }

            if (allowlistScope.Equals("rule", StringComparison.Ordinal))
            {
                ruleAllowlists.Add(allowlist);
            }
            else if (allowlistTargetRules.Count == 0)
            {
                globalAllowlists.Add(allowlist);
            }
            else
            {
                foreach (string ruleId in allowlistTargetRules)
                {
                    if (!targetedGlobalAllowlists.TryGetValue(ruleId, out List<SecretAllowlist>? allowlists))
                    {
                        allowlists = [];
                        targetedGlobalAllowlists.Add(ruleId, allowlists);
                    }

                    allowlists.Add(allowlist);
                }
            }

            hasAllowlist = false;
            allowlistScope = string.Empty;
        }

        void AddCurrentRequiredRule()
        {
            if (!hasRequiredRule)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(requiredRuleId))
            {
                throw new InvalidDataException($"{sourceName}: {id}: [[rules.required]] rule ID is empty");
            }

            ruleRequiredRules.Add(new SecretRequiredRule(requiredRuleId, requiredWithinLines, requiredWithinColumns));
            hasRequiredRule = false;
        }

        void AddCurrentRule()
        {
            if (!hasRule)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(id))
            {
                throw new InvalidDataException($"{sourceName}: rule |id| is missing or empty");
            }

            if (pattern.Length == 0 && pathPattern.Length == 0)
            {
                throw new InvalidDataException($"{sourceName}: {id}: both |regex| and |path| are empty");
            }

            rules.Add(SecretRule.Create(
                id,
                description,
                pattern,
                secretGroup: secretGroup,
                entropy: entropy,
                pathPattern: pathPattern,
                allowlists: ruleAllowlists,
                keywords: keywords,
                tags: tags,
                skipReport: skipReport,
                requiredRules: ruleRequiredRules));
            ruleAllowlists = [];
            ruleRequiredRules = [];
            hasRule = false;
        }

        void ApplyTargetedGlobalAllowlists()
        {
            if (targetedGlobalAllowlists.Count == 0)
            {
                return;
            }

            for (int i = 0; i < rules.Count; i++)
            {
                SecretRule rule = rules[i];
                if (!targetedGlobalAllowlists.TryGetValue(rule.Id, out List<SecretAllowlist>? allowlists))
                {
                    continue;
                }

                rules[i] = CloneRuleWithAdditionalAllowlists(rule, allowlists);
                targetedGlobalAllowlists.Remove(rule.Id);
            }

            if (targetedGlobalAllowlists.Count != 0)
            {
                string missingRuleId = targetedGlobalAllowlists.Keys.First();
                throw new InvalidDataException($"{sourceName}: [[allowlists]] target rule ID '{missingRuleId}' does not exist");
            }
        }

        void ValidateRequiredRules()
        {
            if (rules.Count == 0)
            {
                return;
            }

            var ruleIds = new HashSet<string>(rules.Select(rule => rule.Id), StringComparer.Ordinal);
            foreach (SecretRule rule in rules)
            {
                foreach (SecretRequiredRule requiredRule in rule.RequiredRules)
                {
                    if (!ruleIds.Contains(requiredRule.Id))
                    {
                        throw new InvalidDataException($"{sourceName}: {rule.Id}: [[rules.required]] rule ID '{requiredRule.Id}' does not exist");
                    }
                }
            }
        }
    }

    private static string ReadMultilineValue(string[] lines, ref int lineIndex, string initialValue)
    {
        var value = new StringBuilder(initialValue);
        while (lineIndex + 1 < lines.Length)
        {
            lineIndex++;
            value.Append(' ');
            value.Append(StripComment(lines[lineIndex]).Trim());
            if (!ValueContinues(value.ToString()))
            {
                break;
            }
        }

        return value.ToString();
    }

    private static bool ValueContinues(string value)
    {
        string trimmed = value.TrimStart();
        return trimmed.StartsWith('[')
            && CountOutsideString(value, '[') > CountOutsideString(value, ']');
    }

    private static int CountOutsideString(string value, char needle)
    {
        int mode = 0;
        int count = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (UpdateStringMode(value, ref i, ref mode))
            {
                continue;
            }

            if (mode == 0 && value[i] == needle)
            {
                count++;
            }
        }

        return count;
    }

    private static string StripComment(string line)
    {
        int mode = 0;
        for (int i = 0; i < line.Length; i++)
        {
            if (UpdateStringMode(line, ref i, ref mode))
            {
                continue;
            }

            if (mode == 0 && line[i] == '#')
            {
                return line[..i];
            }
        }

        return line;
    }

    private static bool UpdateStringMode(string value, ref int index, ref int mode)
    {
        if (mode == 0)
        {
            if (StartsWith(value, index, "'''"))
            {
                mode = 4;
                index += 2;
                return true;
            }

            if (StartsWith(value, index, "\"\"\""))
            {
                mode = 3;
                index += 2;
                return true;
            }

            if (value[index] == '\'')
            {
                mode = 2;
                return true;
            }

            if (value[index] == '"')
            {
                mode = 1;
                return true;
            }

            return false;
        }

        if (mode == 1 && value[index] == '"' && !IsEscaped(value, index))
        {
            mode = 0;
            return true;
        }

        if (mode == 2 && value[index] == '\'')
        {
            mode = 0;
            return true;
        }

        if (mode == 3 && StartsWith(value, index, "\"\"\""))
        {
            mode = 0;
            index += 2;
            return true;
        }

        if (mode == 4 && StartsWith(value, index, "'''"))
        {
            mode = 0;
            index += 2;
            return true;
        }

        return false;
    }

    private static bool StartsWith(string value, int index, string prefix)
    {
        return index + prefix.Length <= value.Length
            && value.AsSpan(index, prefix.Length).SequenceEqual(prefix.AsSpan());
    }

    private static bool TrySplitAssignment(string line, out string key, out string value)
    {
        int equalsIndex = line.IndexOf('=');
        if (equalsIndex < 0)
        {
            key = string.Empty;
            value = string.Empty;
            return false;
        }

        key = line[..equalsIndex].Trim();
        value = line[(equalsIndex + 1)..].Trim();
        return key.Length > 0;
    }

    private static string ParseString(string value, string sourceName, string key)
    {
        value = value.Trim();
        if (value.StartsWith("'''", StringComparison.Ordinal) && value.EndsWith("'''", StringComparison.Ordinal) && value.Length >= 6)
        {
            return value[3..^3];
        }

        if (value.StartsWith("\"\"\"", StringComparison.Ordinal) && value.EndsWith("\"\"\"", StringComparison.Ordinal) && value.Length >= 6)
        {
            return UnescapeBasicString(value[3..^3], sourceName, key);
        }

        if (value.StartsWith('\'') && value.EndsWith('\'') && value.Length >= 2)
        {
            return value[1..^1];
        }

        if (value.StartsWith('"') && value.EndsWith('"') && value.Length >= 2)
        {
            return UnescapeBasicString(value[1..^1], sourceName, key);
        }

        throw new InvalidDataException($"{sourceName}: '{key}' must be a TOML string");
    }

    private static List<string> ParseStringArray(string value, string sourceName, string key)
    {
        value = value.Trim();
        if (!value.StartsWith('[') || !value.EndsWith(']'))
        {
            throw new InvalidDataException($"{sourceName}: '{key}' must be a TOML string array");
        }

        var values = new List<string>();
        int index = 1;
        while (index < value.Length - 1)
        {
            while (index < value.Length - 1 && (char.IsWhiteSpace(value[index]) || value[index] == ','))
            {
                index++;
            }

            if (index >= value.Length - 1)
            {
                break;
            }

            values.Add(ParseStringAt(value, ref index, sourceName, key));
        }

        return values;
    }

    private static string ParseStringAt(string value, ref int index, string sourceName, string key)
    {
        if (StartsWith(value, index, "'''"))
        {
            int end = value.IndexOf("'''", index + 3, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new InvalidDataException($"{sourceName}: unterminated string in '{key}'");
            }

            string result = value[(index + 3)..end];
            index = end + 3;
            return result;
        }

        char quote = value[index];
        if (quote is not ('\'' or '"'))
        {
            throw new InvalidDataException($"{sourceName}: '{key}' must contain only strings");
        }

        var builder = new StringBuilder();
        index++;
        while (index < value.Length)
        {
            char c = value[index++];
            if (c == quote && (quote == '\'' || !IsEscaped(value, index - 1)))
            {
                return quote == '"' ? UnescapeBasicString(builder.ToString(), sourceName, key) : builder.ToString();
            }

            builder.Append(c);
        }

        throw new InvalidDataException($"{sourceName}: unterminated string in '{key}'");
    }

    private static int ParseNonNegativeInt(string value, string sourceName, string key)
    {
        if (!int.TryParse(value.Trim(), out int result) || result < 0)
        {
            throw new InvalidDataException($"{sourceName}: '{key}' must be a non-negative integer");
        }

        return result;
    }

    private static bool ParseBoolean(string value, string sourceName, string key)
    {
        if (!bool.TryParse(value.Trim(), out bool result))
        {
            throw new InvalidDataException($"{sourceName}: '{key}' must be a boolean");
        }

        return result;
    }

    private static AllowlistCondition ParseAllowlistCondition(string value, string sourceName, string key)
    {
        string condition = ParseString(value, sourceName, key);
        return condition.ToUpperInvariant() switch
        {
            "" or "OR" or "||" => AllowlistCondition.Or,
            "AND" or "&&" => AllowlistCondition.And,
            _ => throw new InvalidDataException($"{sourceName}: unknown allowlist |condition| '{condition}' (expected 'and', 'or')"),
        };
    }

    private static AllowlistRegexTarget ParseAllowlistRegexTarget(string value, string sourceName, string key)
    {
        string regexTarget = ParseString(value, sourceName, key);
        return regexTarget switch
        {
            "" or "secret" => AllowlistRegexTarget.Secret,
            "match" => AllowlistRegexTarget.Match,
            "line" => AllowlistRegexTarget.Line,
            _ => throw new InvalidDataException($"{sourceName}: unknown allowlist |regexTarget| '{regexTarget}' (expected 'match', 'line')"),
        };
    }

    private static double ParseNonNegativeDouble(string value, string sourceName, string key)
    {
        if (!double.TryParse(value.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out double result)
            || result < 0
            || !double.IsFinite(result))
        {
            throw new InvalidDataException($"{sourceName}: '{key}' must be a non-negative finite number");
        }

        return result;
    }

    private static string UnescapeBasicString(string value, string sourceName, string key)
    {
        var builder = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (c != '\\')
            {
                builder.Append(c);
                continue;
            }

            if (++i >= value.Length)
            {
                throw new InvalidDataException($"{sourceName}: invalid escape in '{key}'");
            }

            builder.Append(value[i] switch
            {
                'b' => '\b',
                't' => '\t',
                'n' => '\n',
                'f' => '\f',
                'r' => '\r',
                '"' => '"',
                '\\' => '\\',
                _ => throw new InvalidDataException($"{sourceName}: unsupported escape in '{key}'"),
            });
        }

        return builder.ToString();
    }

    private static bool IsEscaped(string value, int index)
    {
        int slashCount = 0;
        for (int i = index - 1; i >= 0 && value[i] == '\\'; i--)
        {
            slashCount++;
        }

        return slashCount % 2 == 1;
    }

    private static void ThrowUnsupportedTable(string table, string sourceName)
    {
        switch (table)
        {
            case "rules":
                return;
            case "extend":
                ThrowUnsupported(sourceName, "extend blocks");
                return;
            case "allowlist":
            case "allowlists":
            case "rules.allowlist":
            case "rules.allowlists":
                ThrowUnsupported(sourceName, $"table '{table}'");
                return;
        }
    }

    private static void ThrowUnsupported(string sourceName, string feature)
    {
        throw new NotSupportedException($"{sourceName}: Gitleaks config {feature} are not supported yet");
    }

    private static SecretRule CloneRuleWithAdditionalAllowlists(SecretRule rule, IReadOnlyList<SecretAllowlist> allowlists)
    {
        return SecretRule.Create(
            rule.Id,
            rule.Description,
            rule.Pattern,
            secretGroup: rule.SecretGroup,
            entropy: rule.Entropy,
            pathPattern: rule.PathPattern,
            allowlists: [.. rule.Allowlists, .. allowlists],
            keywords: rule.Keywords,
            tags: rule.Tags,
            skipReport: rule.SkipReport,
            requiredRules: rule.RequiredRules);
    }
}
