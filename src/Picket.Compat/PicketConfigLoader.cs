using Picket.Rules;

namespace Picket.Compat;

/// <summary>
/// Loads Picket-native rule configuration while preserving the Gitleaks-compatible rule schema.
/// </summary>
public static class PicketConfigLoader
{
    private const string PicketConfigEnvironmentVariable = "PICKET_CONFIG";
    private const string PicketConfigTomlEnvironmentVariable = "PICKET_CONFIG_TOML";

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

        return GitleaksConfigLoader.LoadRuleSet(null, source);
    }
}
