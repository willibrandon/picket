using Picket.Rules;

namespace Picket.Compat;

/// <summary>
/// Loads Picket-native rule configuration while preserving the Gitleaks-compatible rule schema.
/// </summary>
public static class PicketConfigLoader
{
    private const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
    private const string GitleaksConfigFileName = ".gitleaks.toml";
    private const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
    private const string PicketConfigEnvironmentVariable = "PICKET_CONFIG";
    private const string PicketConfigTomlEnvironmentVariable = "PICKET_CONFIG_TOML";
    private static readonly Lazy<RuleSet> s_defaultRuleSet = new(LoadEmbeddedDefaultRuleSet);
    private static readonly Lazy<RuleSet> s_experimentalRuleSet = new(LoadEmbeddedExperimentalRuleSet);
    private static readonly Lazy<RuleSet> s_strictRuleSet = new(LoadEmbeddedStrictRuleSet);

    /// <summary>
    /// Loads rules using Picket-native config precedence.
    /// </summary>
    /// <param name="configPath">The explicit config path supplied by <c>--config</c> or <c>-c</c>.</param>
    /// <param name="source">The scan source used to discover compatible target-local config.</param>
    /// <param name="additionalBuiltInRulePacks">Optional built-in rule packs to layer over the resolved native rule set.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet LoadRuleSet(string? configPath, string source, params string[] additionalBuiltInRulePacks)
    {
        ArgumentNullException.ThrowIfNull(additionalBuiltInRulePacks);

        RuleSet ruleSet = LoadResolvedRuleSet(configPath, source);
        return additionalBuiltInRulePacks.Length == 0
            ? ruleSet
            : AddBuiltInRulePacks(ruleSet, additionalBuiltInRulePacks);
    }

    /// <summary>
    /// Loads one built-in rule pack without reading environment variables or target-local configuration files.
    /// </summary>
    /// <param name="rulePack">The stable built-in rule-pack identifier.</param>
    /// <returns>The requested built-in rule pack.</returns>
    public static RuleSet LoadBuiltInRulePack(string rulePack)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePack);

        return rulePack switch
        {
            PicketRulePackNames.Gitleaks => GitleaksConfigLoader.LoadDefaultRuleSet(),
            PicketRulePackNames.Default => SelectRulePack(s_defaultRuleSet.Value, PicketRulePackNames.Default),
            PicketRulePackNames.Strict => s_strictRuleSet.Value,
            PicketRulePackNames.Experimental => s_experimentalRuleSet.Value,
            _ => throw new ArgumentException($"unsupported built-in rule pack: {rulePack}", nameof(rulePack)),
        };
    }

    private static RuleSet LoadResolvedRuleSet(string? configPath, string source)
    {
        if (!string.IsNullOrWhiteSpace(configPath))
        {
            return GitleaksConfigLoader.LoadFile(configPath);
        }

        string? environmentPath = Environment.GetEnvironmentVariable(PicketConfigEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentPath))
        {
            return GitleaksConfigLoader.LoadFile(environmentPath);
        }

        string? environmentToml = Environment.GetEnvironmentVariable(PicketConfigTomlEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentToml))
        {
            return GitleaksConfigLoader.FromToml(environmentToml, PicketConfigTomlEnvironmentVariable);
        }

        string? compatibleEnvironmentPath = Environment.GetEnvironmentVariable(GitleaksConfigEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(compatibleEnvironmentPath))
        {
            return GitleaksConfigLoader.LoadFile(compatibleEnvironmentPath);
        }

        string? compatibleEnvironmentToml = Environment.GetEnvironmentVariable(GitleaksConfigTomlEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(compatibleEnvironmentToml))
        {
            return GitleaksConfigLoader.FromToml(compatibleEnvironmentToml, GitleaksConfigTomlEnvironmentVariable);
        }

        if (Directory.Exists(source))
        {
            string sourceConfigPath = Path.Combine(source, GitleaksConfigFileName);
            if (File.Exists(sourceConfigPath))
            {
                return GitleaksConfigLoader.LoadFile(sourceConfigPath);
            }
        }

        return s_defaultRuleSet.Value;
    }

    /// <summary>
    /// Loads the embedded Picket-native default rule set without reading environment variables or target-local configuration files.
    /// </summary>
    /// <returns>The embedded Picket-native default rule set.</returns>
    public static RuleSet LoadDefaultRuleSet()
    {
        return s_defaultRuleSet.Value;
    }

    private static RuleSet LoadEmbeddedDefaultRuleSet()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            EmbeddedPicketConfig.Toml,
            $"embedded Picket config {EmbeddedPicketConfig.SourceVersion}");
        return new RuleSet(ruleSet.Rules, ruleSet.Allowlists, regexesPrevalidated: true);
    }

    private static RuleSet LoadEmbeddedExperimentalRuleSet()
    {
        return LoadEmbeddedRulePack(
            EmbeddedPicketExperimentalConfig.Toml,
            EmbeddedPicketExperimentalConfig.SourceVersion);
    }

    private static RuleSet LoadEmbeddedStrictRuleSet()
    {
        return LoadEmbeddedRulePack(
            EmbeddedPicketStrictConfig.Toml,
            EmbeddedPicketStrictConfig.SourceVersion);
    }

    private static RuleSet LoadEmbeddedRulePack(string toml, string sourceVersion)
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(toml, $"embedded Picket config {sourceVersion}");
        return new RuleSet(ruleSet.Rules, regexesPrevalidated: true);
    }

    private static RuleSet AddBuiltInRulePacks(RuleSet ruleSet, string[] additionalBuiltInRulePacks)
    {
        var rules = new List<SecretRule>(ruleSet.Rules.Count);
        rules.AddRange(ruleSet.Rules);
        var ruleIds = new HashSet<string>(ruleSet.Rules.Select(static rule => rule.Id), StringComparer.Ordinal);
        bool regexesPrevalidated = ruleSet.RegexesPrevalidated;

        foreach (string rulePackName in additionalBuiltInRulePacks)
        {
            RuleSet additionalRulePack = LoadBuiltInRulePack(rulePackName);
            regexesPrevalidated &= additionalRulePack.RegexesPrevalidated;
            foreach (SecretRule rule in additionalRulePack.Rules)
            {
                if (!ruleIds.Add(rule.Id))
                {
                    throw new InvalidDataException($"duplicate rule ID while layering {rulePackName}: {rule.Id}");
                }

                rules.Add(rule);
            }
        }

        return new RuleSet(rules, ruleSet.Allowlists, regexesPrevalidated);
    }

    private static RuleSet SelectRulePack(RuleSet ruleSet, string rulePackName)
    {
        List<SecretRule> rules = [.. ruleSet.Rules.Where(rule => rule.RulePack.Equals(rulePackName, StringComparison.Ordinal))];
        return new RuleSet(rules, regexesPrevalidated: ruleSet.RegexesPrevalidated);
    }
}
