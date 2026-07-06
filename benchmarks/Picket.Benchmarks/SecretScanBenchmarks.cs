using BenchmarkDotNet.Attributes;
using Picket.Compat;
using Picket.Engine;
using Picket.Rules;

namespace Picket.Benchmarks;

/// <summary>
/// Benchmarks core secret scanning scenarios.
/// </summary>
[MemoryDiagnoser]
public sealed class SecretScanBenchmarks
{
    private byte[] _credentialAnalyzerTests = [];
    private byte[] _embeddedGitleaksConfig = [];
    private CompiledRuleSet _gitleaksCompatibilityRules = null!;
    private CompiledRuleSet _nativeDefaultRules = null!;
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

        RuleSet nativeRules = PicketConfigLoader.LoadRuleSet(null, "__picket-benchmark__");
        _nativeDefaultRules = CompiledRuleSet.Compile(nativeRules);
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

    private static RuleSet SelectRules(RuleSet ruleSet, string ruleId)
    {
        var rules = new List<SecretRule>(1);
        for (int i = 0; i < ruleSet.Rules.Count; i++)
        {
            SecretRule rule = ruleSet.Rules[i];
            if (rule.Id.Equals(ruleId, StringComparison.Ordinal))
            {
                rules.Add(rule);
                break;
            }
        }

        if (rules.Count == 0)
        {
            throw new InvalidDataException($"Could not find benchmark rule '{ruleId}'.");
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
