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

    /// <summary>
    /// Loads rules using Picket-native config precedence.
    /// </summary>
    /// <param name="configPath">The explicit config path supplied by <c>--config</c> or <c>-c</c>.</param>
    /// <param name="source">The scan source used to discover compatible target-local config.</param>
    /// <returns>The loaded rules.</returns>
    public static RuleSet LoadRuleSet(string? configPath, string source)
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

    private static RuleSet LoadEmbeddedDefaultRuleSet()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            EmbeddedPicketConfig.Toml,
            $"embedded Picket config {EmbeddedPicketConfig.SourceVersion}");
        return new RuleSet(ruleSet.Rules, ruleSet.Allowlists, regexesPrevalidated: true);
    }
}
