using Picket.Compat;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksConfigLoader" />.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class GitleaksConfigLoaderTests
{
    /// <summary>
    /// Verifies that the supported Gitleaks TOML rule fields load into scanner rules.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesRegexRuleFields()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            title = "custom config"

            [[rules]]
            id = "custom-token"
            description = ""
            regex = '''token-([A-Z]{4})'''
            path = '''\.txt$'''
            secretGroup = 1
            entropy = 3.5
            keywords = [
                "token",
                'TOKEN2',
            ]
            tags = ["custom", 'example']
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        SecretRule rule = ruleSet.Rules[0];
        Assert.AreEqual("custom-token", rule.Id);
        Assert.AreEqual(string.Empty, rule.Description);
        Assert.AreEqual("token-([A-Z]{4})", rule.Pattern);
        Assert.AreEqual(@"\.txt$", rule.PathPattern);
        Assert.AreEqual(1, rule.SecretGroup);
        Assert.AreEqual(3.5, rule.Entropy);
        Assert.Contains("token", rule.Keywords);
        Assert.Contains("TOKEN2", rule.Keywords);
        Assert.Contains("custom", rule.Tags);
        Assert.Contains("example", rule.Tags);
    }

    /// <summary>
    /// Verifies that an explicit config path wins over every implicit Gitleaks config source.
    /// </summary>
    [TestMethod]
    public void LoadRuleSetUsesExplicitConfigPathFirst()
    {
        string root = CreateTempDirectory();
        string explicitConfigPath = Path.Combine(root, "explicit.toml");
        string environmentConfigPath = Path.Combine(root, "environment.toml");
        string? previousConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            File.WriteAllText(explicitConfigPath, CreateRuleConfig("explicit-rule", "explicit-[0-9]+"));
            File.WriteAllText(environmentConfigPath, CreateRuleConfig("environment-rule", "environment-[0-9]+"));
            File.WriteAllText(Path.Combine(root, ".gitleaks.toml"), CreateRuleConfig("source-rule", "source-[0-9]+"));
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", environmentConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", CreateRuleConfig("inline-rule", "inline-[0-9]+"));

            RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(explicitConfigPath, root);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.AreEqual("explicit-rule", ruleSet.Rules[0].Id);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that inline environment TOML wins over a target-local .gitleaks.toml.
    /// </summary>
    [TestMethod]
    public void LoadRuleSetUsesEnvironmentTomlBeforeSourceConfig()
    {
        string root = CreateTempDirectory();
        string? previousConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            File.WriteAllText(Path.Combine(root, ".gitleaks.toml"), CreateRuleConfig("source-rule", "source-[0-9]+"));
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", null);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", CreateRuleConfig("inline-rule", "inline-[0-9]+"));

            RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(null, root);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.AreEqual("inline-rule", ruleSet.Rules[0].Id);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that unsupported Gitleaks config behavior is rejected instead of silently ignored.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsUnsupportedAllowlistTable()
    {
        Assert.ThrowsExactly<NotSupportedException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''

            [[rules.allowlists]]
            regexes = ['test']
            """,
            "memory"));
    }

    /// <summary>
    /// Verifies that Gitleaks path-only rules load without requiring a content regex.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesPathOnlyRule()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "python-files-only"
            description = "Python Files"
            path = '''.py'''
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.AreEqual("python-files-only", ruleSet.Rules[0].Id);
        Assert.AreEqual(string.Empty, ruleSet.Rules[0].Pattern);
        Assert.AreEqual(".py", ruleSet.Rules[0].PathPattern);
    }

    private static string CreateRuleConfig(string id, string pattern)
    {
        return $$"""
            [[rules]]
            id = "{{id}}"
            regex = '''{{pattern}}'''
            """;
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
