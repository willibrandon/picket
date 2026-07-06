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
    /// Verifies that Gitleaks regex capture groups are counted for secretGroup validation.
    /// </summary>
    [TestMethod]
    public void FromTomlCountsRegexCaptureGroups()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "custom-token"
            regex = '''(?:prefix)[(](?P<name>[A-Z]+)(?<number>[0-9]+)'''
            secretGroup = 2
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.AreEqual(2, ruleSet.Rules[0].SecretGroup);
    }

    /// <summary>
    /// Verifies that invalid secretGroup values are rejected like Gitleaks.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsSecretGroupBeyondRegexCaptures()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "discord-api-key"
            regex = '''(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]'''
            secretGroup = 5
            """,
            "memory"));

        Assert.Contains("discord-api-key: invalid regex secret group 5, max regex secret group 3", exception.Message);
    }

    /// <summary>
    /// Verifies that missing rule IDs include the same helpful context as Gitleaks.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsMissingRuleIdWithContext()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            description = "Discord API key"
            regex = '''(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]'''
            """,
            "memory"));

        Assert.Contains("rule |id| is missing or empty, description: Discord API key, regex: (?i)(discord", exception.Message);
    }

    /// <summary>
    /// Verifies that rules without regex or path use the Gitleaks validation message.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsRuleWithoutRegexOrPath()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "discord-api-key"
            description = "Discord API key"
            """,
            "memory"));

        Assert.Contains("discord-api-key: both |regex| and |path| are empty, this rule will have no effect", exception.Message);
    }

    /// <summary>
    /// Verifies that Gitleaks skipReport rule fields load into scanner rules.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesSkipReportRuleField()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "supporting-rule"
            regex = '''token-[0-9]+'''
            skipReport = true
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.IsTrue(ruleSet.Rules[0].SkipReport);
    }

    /// <summary>
    /// Verifies that Picket-native rule metadata fields load into scanner rules.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesNativeRuleMetadataFields()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''
            severity = "high"
            confidence = "medium"
            rulePack = "picket-strict"
            provider = "custom"
            documentationUrl = "https://example.invalid/rules/custom-token"
            validation = ["offline:custom-token"]
            revocation = ["revocation:custom-token"]
            deprecated = true
            examples = ["token-12345"]
            negativeExamples = ["token-value"]
            """,
            "memory");

        SecretRule rule = ruleSet.Rules[0];
        Assert.AreEqual("high", rule.Severity);
        Assert.AreEqual("medium", rule.Confidence);
        Assert.AreEqual("picket-strict", rule.RulePack);
        Assert.AreEqual("custom", rule.Provider);
        Assert.AreEqual("https://example.invalid/rules/custom-token", rule.DocumentationUrl);
        Assert.HasCount(1, rule.Validation);
        Assert.AreEqual("offline:custom-token", rule.Validation[0]);
        Assert.HasCount(1, rule.Revocation);
        Assert.AreEqual("revocation:custom-token", rule.Revocation[0]);
        Assert.IsTrue(rule.Deprecated);
        Assert.HasCount(1, rule.Examples);
        Assert.AreEqual("token-12345", rule.Examples[0]);
        Assert.HasCount(1, rule.NegativeExamples);
        Assert.AreEqual("token-value", rule.NegativeExamples[0]);
    }

    /// <summary>
    /// Verifies that valid top-level Gitleaks minVersion values are accepted.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesMinVersion()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            minVersion = "v8.25.0"

            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.AreEqual("custom-token", ruleSet.Rules[0].Id);
    }

    /// <summary>
    /// Verifies that invalid top-level Gitleaks minVersion values fail config loading.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsInvalidMinVersion()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            minVersion = "not a version"

            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''
            """,
            "memory"));

        Assert.Contains("invalid minVersion 'not a version'", exception.Message);
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
    /// Verifies that no-config compatibility scans fall back to the pinned embedded Gitleaks config.
    /// </summary>
    [TestMethod]
    public void LoadRuleSetFallsBackToEmbeddedGitleaksDefault()
    {
        string root = CreateTempDirectory();
        string? previousConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", null);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", null);

            RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(null, root);
            List<string> ruleIds = [.. ruleSet.Rules.Select(rule => rule.Id)];

            Assert.HasCount(222, ruleSet.Rules);
            Assert.Contains("aws-access-token", ruleIds);
            Assert.Contains("generic-api-key", ruleIds);
            Assert.Contains("github-pat", ruleIds);
            Assert.Contains("pypi-upload-token", ruleIds);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that strict compatibility config loading ignores Picket-native environment variables.
    /// </summary>
    [TestMethod]
    public void LoadRuleSetIgnoresPicketEnvironmentVariables()
    {
        string root = CreateTempDirectory();
        string? previousPicketConfigPath = Environment.GetEnvironmentVariable("PICKET_CONFIG");
        string? previousPicketConfigToml = Environment.GetEnvironmentVariable("PICKET_CONFIG_TOML");
        string? previousGitleaksConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousGitleaksConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            File.WriteAllText(Path.Combine(root, ".gitleaks.toml"), CreateRuleConfig("source-rule", "source-[0-9]+"));
            Environment.SetEnvironmentVariable("PICKET_CONFIG", null);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", CreateRuleConfig("picket-rule", "picket-[0-9]+"));
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", null);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", null);

            RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(null, root);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.AreEqual("source-rule", ruleSet.Rules[0].Id);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PICKET_CONFIG", previousPicketConfigPath);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", previousPicketConfigToml);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousGitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousGitleaksConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that Picket-native config loading uses PICKET_CONFIG before Gitleaks-compatible environment variables.
    /// </summary>
    [TestMethod]
    public void PicketConfigLoaderUsesPicketConfigBeforeGitleaksConfig()
    {
        string root = CreateTempDirectory();
        string picketConfigPath = Path.Combine(root, "picket.toml");
        string gitleaksConfigPath = Path.Combine(root, "gitleaks.toml");
        string? previousPicketConfigPath = Environment.GetEnvironmentVariable("PICKET_CONFIG");
        string? previousPicketConfigToml = Environment.GetEnvironmentVariable("PICKET_CONFIG_TOML");
        string? previousGitleaksConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousGitleaksConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            File.WriteAllText(picketConfigPath, CreateRuleConfig("picket-rule", "picket-[0-9]+"));
            File.WriteAllText(gitleaksConfigPath, CreateRuleConfig("gitleaks-rule", "gitleaks-[0-9]+"));
            Environment.SetEnvironmentVariable("PICKET_CONFIG", picketConfigPath);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", CreateRuleConfig("picket-inline-rule", "picket-inline-[0-9]+"));
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", gitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", CreateRuleConfig("gitleaks-inline-rule", "gitleaks-inline-[0-9]+"));

            RuleSet ruleSet = PicketConfigLoader.LoadRuleSet(null, root);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.AreEqual("picket-rule", ruleSet.Rules[0].Id);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PICKET_CONFIG", previousPicketConfigPath);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", previousPicketConfigToml);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousGitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousGitleaksConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that Picket-native inline config takes precedence before Gitleaks-compatible environment variables.
    /// </summary>
    [TestMethod]
    public void PicketConfigLoaderUsesPicketConfigTomlBeforeGitleaksConfig()
    {
        string root = CreateTempDirectory();
        string gitleaksConfigPath = Path.Combine(root, "gitleaks.toml");
        string? previousPicketConfigPath = Environment.GetEnvironmentVariable("PICKET_CONFIG");
        string? previousPicketConfigToml = Environment.GetEnvironmentVariable("PICKET_CONFIG_TOML");
        string? previousGitleaksConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousGitleaksConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            File.WriteAllText(gitleaksConfigPath, CreateRuleConfig("gitleaks-rule", "gitleaks-[0-9]+"));
            Environment.SetEnvironmentVariable("PICKET_CONFIG", null);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", CreateRuleConfig("picket-inline-rule", "picket-inline-[0-9]+"));
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", gitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", CreateRuleConfig("gitleaks-inline-rule", "gitleaks-inline-[0-9]+"));

            RuleSet ruleSet = PicketConfigLoader.LoadRuleSet(null, root);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.AreEqual("picket-inline-rule", ruleSet.Rules[0].Id);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PICKET_CONFIG", previousPicketConfigPath);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", previousPicketConfigToml);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousGitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousGitleaksConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that the embedded native default replaces inherited Gitleaks GitHub token rules with Picket-owned rules.
    /// </summary>
    [TestMethod]
    public void PicketConfigLoaderEmbeddedDefaultUsesNativeGitHubRules()
    {
        string root = CreateTempDirectory();
        string? previousPicketConfigPath = Environment.GetEnvironmentVariable("PICKET_CONFIG");
        string? previousPicketConfigToml = Environment.GetEnvironmentVariable("PICKET_CONFIG_TOML");
        string? previousGitleaksConfigPath = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG");
        string? previousGitleaksConfigToml = Environment.GetEnvironmentVariable("GITLEAKS_CONFIG_TOML");
        try
        {
            Environment.SetEnvironmentVariable("PICKET_CONFIG", null);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", null);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", null);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", null);

            RuleSet ruleSet = PicketConfigLoader.LoadRuleSet(null, root);
            List<string> ruleIds = [.. ruleSet.Rules.Select(rule => rule.Id)];

            Assert.Contains("aws-access-token", ruleIds);
            Assert.Contains("picket-github-personal-access-token", ruleIds);
            Assert.Contains("picket-github-fine-grained-personal-access-token", ruleIds);
            Assert.Contains("picket-google-api-key", ruleIds);
            Assert.DoesNotContain("github-pat", ruleIds);
            Assert.DoesNotContain("github-fine-grained-pat", ruleIds);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PICKET_CONFIG", previousPicketConfigPath);
            Environment.SetEnvironmentVariable("PICKET_CONFIG_TOML", previousPicketConfigToml);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG", previousGitleaksConfigPath);
            Environment.SetEnvironmentVariable("GITLEAKS_CONFIG_TOML", previousGitleaksConfigToml);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that Gitleaks required-rule tables load into scanner rules.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesRequiredTable()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''

            [[rules.required]]
            id = "context"
            withinLines = 2
            withinColumns = 10

            [[rules]]
            id = "context"
            regex = '''context'''
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules[0].RequiredRules);
        SecretRequiredRule requiredRule = ruleSet.Rules[0].RequiredRules[0];
        Assert.AreEqual("context", requiredRule.Id);
        Assert.AreEqual(2, requiredRule.WithinLines);
        Assert.AreEqual(10, requiredRule.WithinColumns);
    }

    /// <summary>
    /// Verifies that missing required-rule targets are rejected like Gitleaks.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsMissingRequiredRuleTarget()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''

            [[rules.required]]
            id = "missing"
            """,
            "memory"));

        Assert.Contains("[[rules.required]] rule ID 'missing' does not exist", exception.Message);
    }

    /// <summary>
    /// Verifies that per-rule allowlists are parsed from Gitleaks TOML.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesRuleAllowlist()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "aws-access-key"
            regex = '''AKIA[0-9A-Z]{16}'''

            [[rules.allowlists]]
            regexes = ['''AKIALALEMEL33243OLIA''']
            stopwords = ["example"]
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.HasCount(1, ruleSet.Rules[0].Allowlists);
        SecretAllowlist allowlist = ruleSet.Rules[0].Allowlists[0];
        Assert.Contains("AKIALALEMEL33243OLIA", allowlist.RegexPatterns);
        Assert.Contains("example", allowlist.StopWords);
    }

    /// <summary>
    /// Verifies that top-level targetRules attach global allowlists to matching rules.
    /// </summary>
    [TestMethod]
    public void FromTomlAttachesTargetedGlobalAllowlists()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "github-app-token"
            regex = '''ghs_[0-9A-Za-z]{36}'''

            [[rules]]
            id = "github-oauth"
            regex = '''gho_[0-9A-Za-z]{36}'''

            [[allowlists]]
            targetRules = ["github-app-token"]
            paths = ['''README\.md$''']
            """,
            "memory");

        Assert.IsEmpty(ruleSet.Allowlists);
        Assert.HasCount(1, ruleSet.Rules[0].Allowlists);
        Assert.IsEmpty(ruleSet.Rules[1].Allowlists);
    }

    /// <summary>
    /// Verifies that top-level allowlists without targetRules remain global.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesGlobalAllowlist()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [allowlist]
            paths = ['''vendor/''']

            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Allowlists);
        Assert.Contains("vendor/", ruleSet.Allowlists[0].PathPatterns);
    }

    /// <summary>
    /// Verifies that deprecated and plural global allowlist tables cannot be mixed.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsMixedGlobalAllowlistForms()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [allowlist]
            paths = ['''vendor/''']

            [[allowlists]]
            paths = ['''README\.md$''']

            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """,
            "memory"));

        Assert.Contains("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]", exception.Message);
    }

    /// <summary>
    /// Verifies that deprecated and plural per-rule allowlist tables cannot be mixed on the same rule.
    /// </summary>
    [TestMethod]
    public void FromTomlRejectsMixedRuleAllowlistForms()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(() => GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''

            [rules.allowlist]
            stopwords = ["example"]

            [[rules.allowlists]]
            stopwords = ["sample"]
            """,
            "memory"));

        Assert.Contains("token: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", exception.Message);
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

    /// <summary>
    /// Verifies that extend.url is accepted like Gitleaks even though URL loading is not implemented upstream.
    /// </summary>
    [TestMethod]
    public void FromTomlParsesExtendUrlWithoutLoadingIt()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [extend]
            url = "https://example.invalid/gitleaks.toml"

            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """,
            "memory");

        Assert.HasCount(1, ruleSet.Rules);
        Assert.AreEqual("token", ruleSet.Rules[0].Id);
    }

    /// <summary>
    /// Verifies that extend.useDefault inherits from the embedded Gitleaks default ruleset.
    /// </summary>
    [TestMethod]
    public void FromTomlExtendUseDefaultInheritsEmbeddedGitleaksRules()
    {
        RuleSet ruleSet = GitleaksConfigLoader.FromToml(
            """
            [extend]
            useDefault = true
            disabledRules = ["generic-api-key"]

            [[rules]]
            id = "local-token"
            regex = '''local-[0-9]+'''
            """,
            "memory");
        List<string> ruleIds = [.. ruleSet.Rules.Select(rule => rule.Id)];

        Assert.HasCount(222, ruleSet.Rules);
        Assert.Contains("aws-access-token", ruleIds);
        Assert.Contains("github-pat", ruleIds);
        Assert.Contains("local-token", ruleIds);
        Assert.DoesNotContain("generic-api-key", ruleIds);
    }

    /// <summary>
    /// Verifies that extend.path loads base rules, disables inherited rules, and merges metadata-only overrides.
    /// </summary>
    [TestMethod]
    public void LoadFileExtendsPathAndMergesRuleOverrides()
    {
        string root = CreateTempDirectory();
        try
        {
            string baseConfigPath = Path.Combine(root, "base.toml");
            string childConfigPath = Path.Combine(root, "child.toml");
            File.WriteAllText(
                baseConfigPath,
                """
                [[rules]]
                id = "base-token"
                regex = '''base-[0-9]+'''

                [[rules]]
                id = "disabled-token"
                regex = '''disabled-[0-9]+'''

                [[rules]]
                id = "shared-token"
                description = "base shared"
                regex = '''shared-base-([0-9]+)'''
                path = '''\.txt$'''
                secretGroup = 1
                entropy = 2.1
                keywords = ["base-key"]
                tags = ["base-tag"]

                [[rules.allowlists]]
                stopwords = ["base-example"]
                """);
            File.WriteAllText(
                childConfigPath,
                $$"""
                [extend]
                path = {{CreateTomlLiteral(baseConfigPath)}}
                disabledRules = ["disabled-token"]

                [[rules]]
                id = "shared-token"
                description = "child shared"
                keywords = ["child-key"]
                tags = ["child-tag"]

                [[rules.allowlists]]
                stopwords = ["child-example"]

                [[rules]]
                id = "child-token"
                regex = '''child-[0-9]+'''
                """);

            RuleSet ruleSet = GitleaksConfigLoader.LoadFile(childConfigPath);

            Assert.HasCount(3, ruleSet.Rules);
            Assert.AreEqual("base-token", ruleSet.Rules[0].Id);
            Assert.AreEqual("child-token", ruleSet.Rules[1].Id);
            Assert.AreEqual("shared-token", ruleSet.Rules[2].Id);

            SecretRule sharedRule = ruleSet.Rules[2];
            Assert.AreEqual("child shared", sharedRule.Description);
            Assert.AreEqual("shared-base-([0-9]+)", sharedRule.Pattern);
            Assert.AreEqual(@"\.txt$", sharedRule.PathPattern);
            Assert.AreEqual(1, sharedRule.SecretGroup);
            Assert.AreEqual(2.1, sharedRule.Entropy);
            Assert.Contains("base-key", sharedRule.Keywords);
            Assert.Contains("child-key", sharedRule.Keywords);
            Assert.Contains("base-tag", sharedRule.Tags);
            Assert.Contains("child-tag", sharedRule.Tags);
            Assert.HasCount(2, sharedRule.Allowlists);
            Assert.Contains("base-example", sharedRule.Allowlists[0].StopWords);
            Assert.Contains("child-example", sharedRule.Allowlists[1].StopWords);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that targeted global allowlists can target rules inherited from an extended config.
    /// </summary>
    [TestMethod]
    public void LoadFileAppliesTargetedGlobalAllowlistsAfterExtend()
    {
        string root = CreateTempDirectory();
        try
        {
            string baseConfigPath = Path.Combine(root, "base.toml");
            string childConfigPath = Path.Combine(root, "child.toml");
            File.WriteAllText(baseConfigPath, CreateRuleConfig("base-token", "base-[0-9]+"));
            File.WriteAllText(
                childConfigPath,
                $$"""
                [extend]
                path = {{CreateTomlLiteral(baseConfigPath)}}

                [[allowlists]]
                targetRules = ["base-token"]
                paths = ['''README\.md$''']
                """);

            RuleSet ruleSet = GitleaksConfigLoader.LoadFile(childConfigPath);

            Assert.HasCount(1, ruleSet.Rules);
            Assert.HasCount(1, ruleSet.Rules[0].Allowlists);
            Assert.Contains(@"README\.md$", ruleSet.Rules[0].Allowlists[0].PathPatterns);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateRuleConfig(string id, string pattern)
    {
        return $$"""
            [[rules]]
            id = "{{id}}"
            regex = '''{{pattern}}'''
            """;
    }

    private static string CreateTomlLiteral(string value)
    {
        if (value.Contains("'''", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Test path cannot be represented as a TOML literal string.");
        }

        return $"'''{value}'''";
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
