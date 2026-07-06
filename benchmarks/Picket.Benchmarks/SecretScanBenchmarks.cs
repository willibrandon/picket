using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using Picket.Compat;
using Picket.Engine;
using Picket.Rules;

namespace Picket.Benchmarks;

/// <summary>
/// Benchmarks core secret scanning scenarios.
/// </summary>
[MemoryDiagnoser]
public class SecretScanBenchmarks
{
    private static readonly Dictionary<string, string[]> s_githubSecretScanningRuleIds = new(StringComparer.Ordinal)
    {
        ["google_api_key"] = ["picket-google-api-key"],
    };

    private byte[] _credentialAnalyzerTests = [];
    private byte[] _embeddedGitleaksConfig = [];
    private byte[] _githubSecretScanningFixture = [];
    private CompiledRuleSet _gitleaksCompatibilityRules = null!;
    private CompiledRuleSet _nativeDefaultRules = null!;
    private CompiledRuleSet _nativeGitHubSecretScanningRules = null!;
    private CompiledRuleSet _nativeGoogleApiKeyRule = null!;

    /// <summary>
    /// Loads repository fixtures and compiles benchmark rule sets.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        string repositoryRoot = FindRepositoryRoot();
        _embeddedGitleaksConfig = File.ReadAllBytes(Path.Combine(repositoryRoot, "src", "Picket.Compat", "EmbeddedGitleaksConfig.cs"));
        _credentialAnalyzerTests = File.ReadAllBytes(Path.Combine(repositoryRoot, "tests", "Picket.Tests", "CredentialAnalyzerTests.cs"));
        _githubSecretScanningFixture = CreateGitHubSecretScanningFixture(repositoryRoot);

        RuleSet nativeRules = PicketConfigLoader.LoadRuleSet(null, "__picket-benchmark__");
        _nativeDefaultRules = CompiledRuleSet.Compile(nativeRules);
        _nativeGitHubSecretScanningRules = CompiledRuleSet.Compile(SelectRules(
            nativeRules,
            ReadGitHubSecretScanningRuleIds(Path.Combine(repositoryRoot, "tests", "fixtures", "github-secret-scanning", "alerts.json"))));
        _nativeGoogleApiKeyRule = CompiledRuleSet.Compile(SelectRules(nativeRules, "picket-google-api-key"));
        _gitleaksCompatibilityRules = CompiledRuleSet.Compile(GitleaksConfigLoader.LoadRuleSet(null, "__picket-benchmark__"));
    }

    /// <summary>
    /// Scans the credential analyzer tests with the native default rules.
    /// </summary>
    [Benchmark]
    public int ScanCredentialAnalyzerTestsWithNativeDefault()
    {
        return Scan(_credentialAnalyzerTests, "tests/Picket.Tests/CredentialAnalyzerTests.cs", _nativeDefaultRules);
    }

    /// <summary>
    /// Scans the embedded Gitleaks config with strict Gitleaks-compatible rules.
    /// </summary>
    [Benchmark]
    public int ScanEmbeddedGitleaksConfigWithGitleaksCompatibility()
    {
        return Scan(_embeddedGitleaksConfig, "src/Picket.Compat/EmbeddedGitleaksConfig.cs", _gitleaksCompatibilityRules);
    }

    /// <summary>
    /// Scans the embedded Gitleaks config with native default rules.
    /// </summary>
    [Benchmark]
    public int ScanEmbeddedGitleaksConfigWithNativeDefault()
    {
        return Scan(_embeddedGitleaksConfig, "src/Picket.Compat/EmbeddedGitleaksConfig.cs", _nativeDefaultRules);
    }

    /// <summary>
    /// Scans the embedded Gitleaks config with only the native Google API key rule.
    /// </summary>
    [Benchmark]
    public int ScanEmbeddedGitleaksConfigWithNativeGoogleApiKeyRule()
    {
        return Scan(_embeddedGitleaksConfig, "src/Picket.Compat/EmbeddedGitleaksConfig.cs", _nativeGoogleApiKeyRule);
    }

    /// <summary>
    /// Scans the sanitized GitHub secret-scanning oracle fixture with mapped native rules.
    /// </summary>
    [Benchmark]
    public int ScanGitHubSecretScanningOracleFixtureWithMappedNativeRules()
    {
        return Scan(_githubSecretScanningFixture, "tests/fixtures/github-secret-scanning/source-template.txt", _nativeGitHubSecretScanningRules);
    }

    /// <summary>
    /// Compiles the native default rules.
    /// </summary>
    [Benchmark]
    public string CompileNativeDefaultRules()
    {
        return CompiledRuleSet.Compile(PicketConfigLoader.LoadRuleSet(null, "__picket-benchmark__")).Fingerprint;
    }

    private static int Scan(byte[] input, string fileName, CompiledRuleSet rules)
    {
        return SecretScanner.Scan(new ScanRequest(input, fileName, rules, maxDecodeDepth: 0)).Count;
    }

    private static byte[] CreateGitHubSecretScanningFixture(string repositoryRoot)
    {
        string template = File.ReadAllText(Path.Combine(repositoryRoot, "tests", "fixtures", "github-secret-scanning", "source-template.txt"));
        string fixture = template.Replace("{{GOOGLE_API_KEY}}", CreateGcpApiKey(), StringComparison.Ordinal);
        return Encoding.UTF8.GetBytes(fixture);
    }

    private static string CreateGcpApiKey()
    {
        return string.Concat(CreateGcpApiKeyPrefix(), "SyDabcdefghijklmnopqrstuvwxyz123456");
    }

    private static string CreateGcpApiKeyPrefix()
    {
        return string.Concat("AI", "za");
    }

    private static string[] ReadGitHubSecretScanningRuleIds(string alertsPath)
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(alertsPath));
        JsonElement root = document.RootElement;
        var ruleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement alert in root.GetProperty("Alerts").EnumerateArray())
        {
            string? secretType = alert.GetProperty("SecretType").GetString();
            if (secretType is null || !s_githubSecretScanningRuleIds.TryGetValue(secretType, out string[]? mappedRuleIds))
            {
                continue;
            }

            foreach (string ruleId in mappedRuleIds)
            {
                ruleIds.Add(ruleId);
            }
        }

        if (ruleIds.Count == 0)
        {
            throw new InvalidDataException($"No mapped GitHub secret-scanning alert types were found in '{alertsPath}'.");
        }

        return [.. ruleIds.Order(StringComparer.Ordinal)];
    }

    private static RuleSet SelectRules(RuleSet ruleSet, string ruleId)
    {
        return SelectRules(ruleSet, [ruleId]);
    }

    private static RuleSet SelectRules(RuleSet ruleSet, string[] ruleIds)
    {
        var selectedRuleIds = new HashSet<string>(ruleIds, StringComparer.Ordinal);
        var rules = new List<SecretRule>(selectedRuleIds.Count);
        for (int i = 0; i < ruleSet.Rules.Count; i++)
        {
            SecretRule rule = ruleSet.Rules[i];
            if (selectedRuleIds.Contains(rule.Id))
            {
                rules.Add(rule);
            }
        }

        if (rules.Count != selectedRuleIds.Count)
        {
            string missingRuleIds = string.Join(", ", selectedRuleIds.Except(rules.Select(rule => rule.Id), StringComparer.Ordinal));
            throw new InvalidDataException($"Could not find benchmark rule IDs: {missingRuleIds}.");
        }

        return new RuleSet(rules, ruleSet.Allowlists, ruleSet.RegexesPrevalidated);
    }

    private static string FindRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory, "Picket.slnx")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
