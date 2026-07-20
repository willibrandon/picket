using BenchmarkDotNet.Attributes;
using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Benchmarks;

/// <summary>
/// Benchmarks capture extraction and shared structured parsing at representative scales.
/// </summary>
[MemoryDiagnoser]
public class NativeMatchingBenchmarks
{
    private byte[] _capturedMatchInput = [];
    private CompiledRuleSet _capturedMatchRules = null!;
    private byte[] _structuredJsonInput = [];
    private CompiledRuleSet _structuredJsonRules = null!;

    /// <summary>
    /// Gets or sets the number of records in each generated benchmark input.
    /// </summary>
    [Params(100, 5000)]
    public int RecordCount { get; set; }

    /// <summary>
    /// Creates deterministic inputs and compiles the benchmark rule sets.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        _capturedMatchInput = CreateCapturedMatchInput(RecordCount);
        _structuredJsonInput = CreateStructuredJsonInput(RecordCount);
        _capturedMatchRules = CompiledRuleSet.Compile(new RuleSet(
            [SecretRule.Create(
                "benchmark-captured-token",
                "Benchmark captured token.",
                "token=([A-Za-z0-9_-]{32})",
                secretGroup: 1,
                keywords: ["token="])]));
        _structuredJsonRules = CompiledRuleSet.Compile(CreateStructuredJsonRuleSet());
        _capturedMatchRules.CompileDeferredRegexes();
        _structuredJsonRules.CompileDeferredRegexes();
    }

    /// <summary>
    /// Scans a finding-dense input while reusing each regex capture result.
    /// </summary>
    /// <returns>The number of findings.</returns>
    [Benchmark]
    public int ScanCapturedMatches()
    {
        return SecretScanner.Scan(new ScanRequest(
            _capturedMatchInput,
            "captured-matches.txt",
            _capturedMatchRules,
            maxDecodeDepth: 0)).Count;
    }

    /// <summary>
    /// Scans one JSON document with every built-in JSON credential detector.
    /// </summary>
    /// <returns>The number of findings.</returns>
    [Benchmark]
    public int ScanStructuredJsonCredentials()
    {
        return SecretScanner.Scan(new ScanRequest(
            _structuredJsonInput,
            "mcp.json",
            _structuredJsonRules,
            maxDecodeDepth: 0)
        {
            EnableNativeDetectors = true,
            PositionKind = FindingPositionKind.UnicodeCodePointsExclusive,
        }).Count;
    }

    private static byte[] CreateCapturedMatchInput(int recordCount)
    {
        var builder = new StringBuilder(recordCount * 48);
        for (int i = 0; i < recordCount; i++)
        {
            builder.Append("token=a8F2kL9mQ4xT7vN1zR6pW3cY");
            builder.Append((i % 100000000).ToString("D8", System.Globalization.CultureInfo.InvariantCulture));
            builder.Append('\n');
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static byte[] CreateStructuredJsonInput(int recordCount)
    {
        var random = new Random(42);
        var builder = new StringBuilder(recordCount * 112);
        builder.Append("{\"tokens\":{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwaWNrZXQifQ.signature_value\",\"refresh_token\":\"rt_a8F2kL9mQ4xT7vN1zR6pW3cY5uH0jK8sD2qP9bX4nM7wE1tL\"},");
        builder.Append("\"auths\":{\"registry.example.com\":{\"auth\":\"cGlja2V0LXVzZXI6cGlja2V0LXBhc3N3b3Jk\"}},");
        builder.Append("\"serviceAccount\":{\"type\":\"service_account\",\"client_email\":\"scanner@example.iam.gserviceaccount.com\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nQUJD\\n-----END PRIVATE KEY-----\\n\"},");
        builder.Append("\"jwk\":{\"kty\":\"RSA\",\"n\":\"0123456789abcdefghijklmnopqrstuvwxyz_ABCD\",\"e\":\"AQAB\",\"d\":\"0123456789abcdefghijklmnopqrstuvwxyz_ABCD\"},");
        builder.Append("\"mcpServers\":{");
        byte[] randomBytes = new byte[36];
        for (int i = 0; i < recordCount; i++)
        {
            builder.Append(i == 0 ? '\n' : ',');
            if (i != 0)
            {
                builder.Append('\n');
            }

            random.NextBytes(randomBytes);
            string credential = Convert.ToBase64String(randomBytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            builder.Append("\"server");
            builder.Append(i);
            builder.Append("\":{\"env\":{\"SERVER_");
            builder.Append(i);
            builder.Append("_API_KEY\":\"");
            builder.Append(credential);
            builder.Append("\",\"LOG_LEVEL\":\"info\"}}");
        }

        builder.Append("\n}}");
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static RuleSet CreateStructuredJsonRuleSet()
    {
        RuleSet nativeRules = PicketConfigLoader.LoadRuleSet(null, "__picket-benchmark__");
        var selected = new List<SecretRule>();
        for (int i = 0; i < nativeRules.Rules.Count; i++)
        {
            SecretRule rule = nativeRules.Rules[i];
            if (rule.Detector is PicketBuiltInDetectorNames.CodexCredentials
                or PicketBuiltInDetectorNames.DockerRegistryCredentials
                or PicketBuiltInDetectorNames.GcpServiceAccountKey
                or PicketBuiltInDetectorNames.JwkPrivateKey
                or PicketBuiltInDetectorNames.McpServerCredentials)
            {
                selected.Add(rule);
            }
        }

        return new RuleSet(selected, nativeRules.Allowlists, nativeRules.RegexesPrevalidated);
    }
}
