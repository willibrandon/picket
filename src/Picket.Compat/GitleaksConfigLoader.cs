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
    private const long MaxConfigFileBytes = 10 * 1024 * 1024;
    private const int MaxExtendDepth = 2;
    private static readonly Lazy<RuleSet> s_defaultRuleSet = new(LoadEmbeddedDefaultRuleSet);

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

        return s_defaultRuleSet.Value;
    }

    /// <summary>
    /// Loads the embedded Gitleaks-compatible default rule set without reading environment variables or target-local configuration files.
    /// </summary>
    /// <returns>The embedded Gitleaks-compatible default rule set.</returns>
    public static RuleSet LoadDefaultRuleSet()
    {
        return s_defaultRuleSet.Value;
    }

    /// <summary>
    /// Loads rules from a Gitleaks TOML file.
    /// </summary>
    /// <param name="path">The TOML file path.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet LoadFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return LoadFile(path, 0, []);
    }

    /// <summary>
    /// Loads rules from Gitleaks TOML content.
    /// </summary>
    /// <param name="toml">The TOML content.</param>
    /// <param name="sourceName">The source name used in diagnostics.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet FromToml(string toml, string sourceName)
    {
        return FromToml(toml, sourceName, 0, null);
    }

    private static RuleSet LoadFile(string path, int extendDepth, HashSet<string> visitedPaths)
    {
        string fullPath = Path.GetFullPath(path);
        if (!visitedPaths.Add(fullPath))
        {
            throw new InvalidDataException($"{path}: extend.path cycle detected");
        }

        try
        {
            return FromToml(ReadConfigText(fullPath), fullPath, extendDepth, visitedPaths);
        }
        finally
        {
            visitedPaths.Remove(fullPath);
        }
    }

    private static string ReadConfigText(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 8192, FileOptions.SequentialScan);
        if (stream.CanSeek && stream.Length > MaxConfigFileBytes)
        {
            throw new InvalidDataException($"{path}: config file exceeds {MaxConfigFileBytes.ToString(CultureInfo.InvariantCulture)} bytes");
        }

        var content = new MemoryStream();
        var buffer = new byte[8192];
        long totalBytes = 0;
        int read;
        while ((read = stream.Read(buffer.AsSpan())) != 0)
        {
            totalBytes += read;
            if (totalBytes > MaxConfigFileBytes)
            {
                throw new InvalidDataException($"{path}: config file exceeds {MaxConfigFileBytes.ToString(CultureInfo.InvariantCulture)} bytes");
            }

            content.Write(buffer.AsSpan(0, read));
        }

        content.Position = 0;
        using var reader = new StreamReader(content, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static RuleSet FromToml(string toml, string sourceName, int extendDepth, HashSet<string>? visitedPaths)
    {
        ArgumentNullException.ThrowIfNull(toml);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceName);

        var rules = new List<GitleaksRuleDefinition>();
        var globalAllowlists = new List<SecretAllowlist>();
        var targetedGlobalAllowlists = new Dictionary<string, List<SecretAllowlist>>(StringComparer.Ordinal);
        var ruleAllowlists = new List<SecretAllowlist>();
        var ruleRequiredRules = new List<SecretRequiredRule>();
        string section = string.Empty;
        string allowlistScope = string.Empty;
        bool hasRule = false;
        bool hasAllowlist = false;
        bool hasRequiredRule = false;
        bool globalDeprecatedAllowlistSeen = false;
        bool globalPluralAllowlistsSeen = false;
        bool ruleDeprecatedAllowlistSeen = false;
        bool rulePluralAllowlistsSeen = false;
        string id = string.Empty;
        string description = string.Empty;
        string pattern = string.Empty;
        string pathPattern = string.Empty;
        int secretGroup = 0;
        double entropy = 0;
        bool skipReport = false;
        IReadOnlyList<string> keywords = [];
        IReadOnlyList<string> tags = [];
        string severity = string.Empty;
        string confidence = string.Empty;
        string rulePack = string.Empty;
        string provider = string.Empty;
        string documentationUrl = string.Empty;
        IReadOnlyList<string> validation = [];
        IReadOnlyList<string> revocation = [];
        bool deprecated = false;
        IReadOnlyList<string> examples = [];
        IReadOnlyList<string> negativeExamples = [];
        string minVersion = string.Empty;
        string allowlistDescription = string.Empty;
        AllowlistCondition allowlistCondition = AllowlistCondition.Or;
        List<string> allowlistCommits = [];
        List<string> allowlistPaths = [];
        AllowlistRegexTarget allowlistRegexTarget = AllowlistRegexTarget.Secret;
        List<string> allowlistRegexes = [];
        List<string> allowlistStopWords = [];
        List<string> allowlistTargetRules = [];
        string extendPath = string.Empty;
        bool extendUseDefault = false;
        List<string> extendDisabledRules = [];
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
                    ruleDeprecatedAllowlistSeen = false;
                    rulePluralAllowlistsSeen = false;
                    id = string.Empty;
                    description = string.Empty;
                    pattern = string.Empty;
                    pathPattern = string.Empty;
                    secretGroup = 0;
                    entropy = 0;
                    skipReport = false;
                    keywords = [];
                    tags = [];
                    severity = string.Empty;
                    confidence = string.Empty;
                    rulePack = string.Empty;
                    provider = string.Empty;
                    documentationUrl = string.Empty;
                    validation = [];
                    revocation = [];
                    deprecated = false;
                    examples = [];
                    negativeExamples = [];
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
                    CheckRuleAllowlistStyle(deprecated: false);
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
                    CheckGlobalAllowlistStyle(deprecated: false);
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
                if (table.Equals("extend", StringComparison.Ordinal))
                {
                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    AddCurrentRule();
                    section = "extend";
                    continue;
                }

                if (table.Equals("rules.allowlist", StringComparison.Ordinal))
                {
                    if (!hasRule)
                    {
                        throw new InvalidDataException($"{sourceName}: [rules.allowlist] must follow a [[rules]] entry");
                    }

                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    CheckRuleAllowlistStyle(deprecated: true);
                    StartAllowlist("rule");
                    continue;
                }

                if (table.Equals("allowlist", StringComparison.Ordinal))
                {
                    AddCurrentAllowlist();
                    AddCurrentRequiredRule();
                    AddCurrentRule();
                    CheckGlobalAllowlistStyle(deprecated: true);
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

            if (section.Length == 0)
            {
                if (key.Equals("minVersion", StringComparison.Ordinal))
                {
                    minVersion = ParseString(value, sourceName, key);
                }

                continue;
            }

            if (section.Equals("extend", StringComparison.Ordinal))
            {
                switch (key)
                {
                    case "path":
                        extendPath = ParseString(value, sourceName, key);
                        break;
                    case "url":
                        _ = ParseString(value, sourceName, key);
                        break;
                    case "useDefault":
                        extendUseDefault = ParseBoolean(value, sourceName, key);
                        break;
                    case "disabledRules":
                        extendDisabledRules = ParseStringArray(value, sourceName, key);
                        break;
                }

                continue;
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
                case "severity":
                    severity = ParseString(value, sourceName, key);
                    break;
                case "confidence":
                    confidence = ParseString(value, sourceName, key);
                    break;
                case "rulePack":
                    rulePack = ParseString(value, sourceName, key);
                    break;
                case "provider":
                    provider = ParseString(value, sourceName, key);
                    break;
                case "documentationUrl":
                    documentationUrl = ParseString(value, sourceName, key);
                    break;
                case "validation":
                    validation = ParseStringArray(value, sourceName, key);
                    break;
                case "revocation":
                    revocation = ParseStringArray(value, sourceName, key);
                    break;
                case "deprecated":
                    deprecated = ParseBoolean(value, sourceName, key);
                    break;
                case "examples":
                    examples = ParseStringArray(value, sourceName, key);
                    break;
                case "negativeExamples":
                    negativeExamples = ParseStringArray(value, sourceName, key);
                    break;
            }
        }

        AddCurrentAllowlist();
        AddCurrentRequiredRule();
        AddCurrentRule();
        ValidateMinVersion(minVersion, sourceName);
        ResolveExtends();
        ApplyTargetedGlobalAllowlists();
        if (rules.Count == 0)
        {
            throw new InvalidDataException($"{sourceName}: no [[rules]] entries were found");
        }

        List<SecretRule> loadedRules = CreateRules();
        ValidateRequiredRules(loadedRules);
        return new RuleSet(loadedRules, globalAllowlists);

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

        void CheckGlobalAllowlistStyle(bool deprecated)
        {
            if (deprecated)
            {
                globalDeprecatedAllowlistSeen = true;
                if (globalPluralAllowlistsSeen)
                {
                    throw new InvalidDataException($"{sourceName}: [allowlist] is deprecated, it cannot be used alongside [[allowlists]]");
                }

                return;
            }

            globalPluralAllowlistsSeen = true;
            if (globalDeprecatedAllowlistSeen)
            {
                throw new InvalidDataException($"{sourceName}: [allowlist] is deprecated, it cannot be used alongside [[allowlists]]");
            }
        }

        void CheckRuleAllowlistStyle(bool deprecated)
        {
            if (deprecated)
            {
                ruleDeprecatedAllowlistSeen = true;
                if (rulePluralAllowlistsSeen)
                {
                    throw new InvalidDataException($"{sourceName}: {id}: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]");
                }

                return;
            }

            rulePluralAllowlistsSeen = true;
            if (ruleDeprecatedAllowlistSeen)
            {
                throw new InvalidDataException($"{sourceName}: {id}: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]");
            }
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

            if (rules.Count >= RuleSet.MaxRuleCount)
            {
                throw new InvalidDataException($"{sourceName}: rule count exceeds maximum of {RuleSet.MaxRuleCount.ToString(CultureInfo.InvariantCulture)} entries");
            }

            if (string.IsNullOrWhiteSpace(id))
            {
                throw new InvalidDataException($"{sourceName}: {GitleaksRuleDefinition.CreateMissingIdMessage(description, pattern, pathPattern)}");
            }

            rules.Add(new GitleaksRuleDefinition(
                id,
                description,
                pattern,
                secretGroup,
                entropy,
                pathPattern,
                ruleAllowlists,
                keywords,
                tags,
                skipReport,
                ruleRequiredRules,
                severity,
                confidence,
                rulePack,
                provider,
                documentationUrl,
                validation,
                revocation,
                deprecated,
                examples,
                negativeExamples));
            ruleAllowlists = [];
            ruleRequiredRules = [];
            hasRule = false;
            ruleDeprecatedAllowlistSeen = false;
            rulePluralAllowlistsSeen = false;
        }

        void ResolveExtends()
        {
            if (extendDepth >= MaxExtendDepth)
            {
                return;
            }

            if (extendPath.Length != 0 && extendUseDefault)
            {
                throw new InvalidDataException($"{sourceName}: unable to load config due to extend.path and extend.useDefault being set");
            }

            RuleSet? extendedRuleSet = null;
            if (extendUseDefault)
            {
                extendedRuleSet = s_defaultRuleSet.Value;
            }
            else if (extendPath.Length != 0)
            {
                try
                {
                    extendedRuleSet = LoadFile(extendPath, extendDepth + 1, visitedPaths ?? []);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException)
                {
                    throw new InvalidDataException($"{sourceName}: failed to load extended config '{extendPath}': {exception.Message}", exception);
                }
            }

            if (extendedRuleSet is null)
            {
                return;
            }

            var disabledRules = new HashSet<string>(extendDisabledRules, StringComparer.Ordinal);
            var mergedRules = new Dictionary<string, GitleaksRuleDefinition>(StringComparer.Ordinal);
            foreach (GitleaksRuleDefinition rule in rules)
            {
                mergedRules[rule.Id] = rule;
            }

            foreach (SecretRule baseRule in extendedRuleSet.Rules)
            {
                if (disabledRules.Contains(baseRule.Id))
                {
                    continue;
                }

                if (mergedRules.TryGetValue(baseRule.Id, out GitleaksRuleDefinition? currentRule))
                {
                    mergedRules[baseRule.Id] = currentRule.MergeWithBase(baseRule);
                }
                else
                {
                    mergedRules.Add(baseRule.Id, GitleaksRuleDefinition.FromRule(baseRule));
                }
            }

            rules = [.. mergedRules.Values.OrderBy(rule => rule.Id, StringComparer.Ordinal)];
            ValidateRuleCount();
            globalAllowlists.AddRange(extendedRuleSet.Allowlists);
        }

        void ValidateRuleCount()
        {
            if (rules.Count > RuleSet.MaxRuleCount)
            {
                throw new InvalidDataException($"{sourceName}: rule count exceeds maximum of {RuleSet.MaxRuleCount.ToString(CultureInfo.InvariantCulture)} entries");
            }
        }

        void ApplyTargetedGlobalAllowlists()
        {
            if (targetedGlobalAllowlists.Count == 0)
            {
                return;
            }

            for (int i = 0; i < rules.Count; i++)
            {
                GitleaksRuleDefinition rule = rules[i];
                if (!targetedGlobalAllowlists.TryGetValue(rule.Id, out List<SecretAllowlist>? allowlists))
                {
                    continue;
                }

                rules[i] = rule.WithAdditionalAllowlists(allowlists);
                targetedGlobalAllowlists.Remove(rule.Id);
            }

            if (targetedGlobalAllowlists.Count != 0)
            {
                string missingRuleId = targetedGlobalAllowlists.Keys.First();
                throw new InvalidDataException($"{sourceName}: [[allowlists]] target rule ID '{missingRuleId}' does not exist");
            }
        }

        List<SecretRule> CreateRules()
        {
            var loadedRules = new List<SecretRule>(rules.Count);
            foreach (GitleaksRuleDefinition rule in rules)
            {
                loadedRules.Add(rule.ToRule(sourceName));
            }

            return loadedRules;
        }

        void ValidateRequiredRules(IReadOnlyList<SecretRule> loadedRules)
        {
            if (loadedRules.Count == 0)
            {
                return;
            }

            var ruleIds = new HashSet<string>(loadedRules.Select(rule => rule.Id), StringComparer.Ordinal);
            foreach (SecretRule rule in loadedRules)
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
        if (!TryGetArrayContinuationState(initialValue, out int arrayDepth, out int stringMode))
        {
            return value.ToString();
        }

        while (lineIndex + 1 < lines.Length)
        {
            lineIndex++;
            value.Append(' ');
            string nextLine = StripComment(lines[lineIndex]).Trim();
            value.Append(nextLine);
            UpdateArrayContinuationState(nextLine, ref arrayDepth, ref stringMode);
            if (arrayDepth <= 0)
            {
                break;
            }
        }

        return value.ToString();
    }

    private static bool ValueContinues(string value)
    {
        return TryGetArrayContinuationState(value, out int arrayDepth, out _)
            && arrayDepth > 0;
    }

    private static bool TryGetArrayContinuationState(string value, out int arrayDepth, out int stringMode)
    {
        arrayDepth = 0;
        stringMode = 0;
        string trimmed = value.TrimStart();
        if (!trimmed.StartsWith('['))
        {
            return false;
        }

        UpdateArrayContinuationState(value, ref arrayDepth, ref stringMode);
        return true;
    }

    private static void UpdateArrayContinuationState(string value, ref int arrayDepth, ref int stringMode)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (UpdateStringMode(value, ref i, ref stringMode))
            {
                continue;
            }

            if (stringMode == 0 && value[i] == '[')
            {
                arrayDepth++;
            }
            else if (stringMode == 0 && value[i] == ']')
            {
                arrayDepth--;
            }
        }
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

            switch (value[i])
            {
                case 'b':
                    builder.Append('\b');
                    break;
                case 't':
                    builder.Append('\t');
                    break;
                case 'n':
                    builder.Append('\n');
                    break;
                case 'f':
                    builder.Append('\f');
                    break;
                case 'r':
                    builder.Append('\r');
                    break;
                case '"':
                    builder.Append('"');
                    break;
                case '\\':
                    builder.Append('\\');
                    break;
                case 'u':
                    builder.Append(ReadUnicodeEscape(value, i + 1, 4, sourceName, key));
                    i += 4;
                    break;
                case 'U':
                    builder.Append(ReadUnicodeEscape(value, i + 1, 8, sourceName, key));
                    i += 8;
                    break;
                default:
                    throw new InvalidDataException($"{sourceName}: unsupported escape in '{key}'");
            }
        }

        return builder.ToString();
    }

    private static string ReadUnicodeEscape(string value, int start, int digitCount, string sourceName, string key)
    {
        if (start + digitCount > value.Length)
        {
            throw new InvalidDataException($"{sourceName}: invalid unicode escape in '{key}'");
        }

        uint codePoint = 0;
        for (int i = start; i < start + digitCount; i++)
        {
            int digit = HexDigitValue(value[i]);
            if (digit < 0)
            {
                throw new InvalidDataException($"{sourceName}: invalid unicode escape in '{key}'");
            }

            codePoint = (codePoint << 4) | (uint)digit;
        }

        if (codePoint > 0x10FFFF || codePoint is >= 0xD800 and <= 0xDFFF)
        {
            throw new InvalidDataException($"{sourceName}: invalid unicode scalar in '{key}'");
        }

        return char.ConvertFromUtf32((int)codePoint);
    }

    private static int HexDigitValue(char value)
    {
        return value switch
        {
            >= '0' and <= '9' => value - '0',
            >= 'A' and <= 'F' => value - 'A' + 10,
            >= 'a' and <= 'f' => value - 'a' + 10,
            _ => -1,
        };
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

    private static void ValidateMinVersion(string value, string sourceName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        string version = value.Trim();
        if (version.StartsWith('v') || version.StartsWith('V'))
        {
            version = version[1..];
        }

        if (!IsValidVersion(version))
        {
            throw new InvalidDataException($"{sourceName}: invalid minVersion '{value}'");
        }
    }

    private static bool IsValidVersion(string version)
    {
        if (version.Length == 0)
        {
            return false;
        }

        int buildIndex = version.IndexOf('+', StringComparison.Ordinal);
        if (buildIndex >= 0)
        {
            string build = version[(buildIndex + 1)..];
            version = version[..buildIndex];
            if (!IsValidVersionSuffix(build))
            {
                return false;
            }
        }

        int prereleaseIndex = version.IndexOf('-', StringComparison.Ordinal);
        if (prereleaseIndex >= 0)
        {
            string prerelease = version[(prereleaseIndex + 1)..];
            version = version[..prereleaseIndex];
            if (!IsValidVersionSuffix(prerelease))
            {
                return false;
            }
        }

        return IsValidNumericVersion(version);
    }

    private static bool IsValidNumericVersion(string version)
    {
        string[] parts = version.Split('.');
        if (parts.Length == 0 || parts.Length > 4)
        {
            return false;
        }

        foreach (string part in parts)
        {
            if (part.Length == 0)
            {
                return false;
            }

            foreach (char c in part)
            {
                if (!char.IsAsciiDigit(c))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsValidVersionSuffix(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        string[] identifiers = value.Split('.');
        foreach (string identifier in identifiers)
        {
            if (identifier.Length == 0)
            {
                return false;
            }

            foreach (char c in identifier)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static void ThrowUnsupportedTable(string table, string sourceName)
    {
        switch (table)
        {
            case "rules":
            case "extend":
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
        throw new NotSupportedException($"{sourceName}: Gitleaks config {feature} is not supported");
    }

    private static RuleSet LoadEmbeddedDefaultRuleSet()
    {
        RuleSet ruleSet = FromToml(
            EmbeddedGitleaksConfig.Toml,
            $"embedded Gitleaks config {EmbeddedGitleaksConfig.SourceVersion} ({EmbeddedGitleaksConfig.SourceCommit})",
            MaxExtendDepth,
            null);
        return new RuleSet(ruleSet.Rules, ruleSet.Allowlists, regexesPrevalidated: true);
    }
}
