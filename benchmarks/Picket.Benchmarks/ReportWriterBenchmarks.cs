using BenchmarkDotNet.Attributes;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Benchmarks;

/// <summary>
/// Benchmarks report writer throughput and allocation behavior.
/// </summary>
[MemoryDiagnoser]
public class ReportWriterBenchmarks
{
    private List<Finding> _findings = [];
    private List<SecretRule> _rules = [];

    /// <summary>
    /// Gets or sets the number of findings emitted by each report writer benchmark.
    /// </summary>
    [Params(1, 100, 1000)]
    public int FindingCount { get; set; }

    /// <summary>
    /// Creates deterministic findings and rules for each benchmark size.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        _rules = CreateRules();
        _findings = CreateFindings(FindingCount);
    }

    /// <summary>
    /// Writes a Gitleaks-compatible JSON report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark(Baseline = true)]
    public string WriteGitleaksJson()
    {
        return GitleaksJsonReportWriter.Write(_findings);
    }

    /// <summary>
    /// Writes a Picket-native rich JSON report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark]
    public string WritePicketJson()
    {
        return PicketJsonReportWriter.Write(_findings, _rules);
    }

    /// <summary>
    /// Writes a Picket-native JSON Lines report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark]
    public string WritePicketJsonLines()
    {
        return PicketJsonlReportWriter.Write(_findings, _rules);
    }

    /// <summary>
    /// Writes a Picket-native SARIF report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark]
    public string WritePicketSarif()
    {
        return PicketSarifReportWriter.Write(_findings, _rules);
    }

    /// <summary>
    /// Writes a Picket-native HTML report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark]
    public string WritePicketHtml()
    {
        return PicketHtmlReportWriter.Write(_findings, _rules);
    }

    /// <summary>
    /// Writes a Picket-native TOON report.
    /// </summary>
    /// <returns>The generated report text.</returns>
    [Benchmark]
    public string WritePicketToon()
    {
        return PicketToonReportWriter.Write(_findings, _rules);
    }

    private static List<SecretRule> CreateRules()
    {
        return
        [
            SecretRule.Create(
                "picket-github-personal-access-token",
                "GitHub personal access token",
                @"\b(ghp_[0-9A-Za-z]{36})\b",
                secretGroup: 1,
                keywords: ["ghp_"],
                tags: ["github", "token"],
                severity: "critical",
                confidence: "high",
                rulePack: "picket-default",
                provider: "GitHub",
                documentationUrl: "https://docs.github.com/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token"),
            SecretRule.Create(
                "picket-google-api-key",
                "Google API key",
                @"\b(AIza[0-9A-Za-z_-]{35})\b",
                secretGroup: 1,
                keywords: ["AIza"],
                tags: ["gcp", "api-key"],
                severity: "high",
                confidence: "high",
                rulePack: "picket-default",
                provider: "GCP",
                documentationUrl: "https://cloud.google.com/docs/authentication/api-keys"),
        ];
    }

    private static List<Finding> CreateFindings(int count)
    {
        var findings = new List<Finding>(count);
        for (int i = 0; i < count; i++)
        {
            bool github = i % 2 == 0;
            string secret = github ? CreateGitHubToken(i) : CreateGoogleApiKey(i);
            string ruleId = github ? "picket-github-personal-access-token" : "picket-google-api-key";
            string file = github ? $"src/github-{i}.cs" : $"src/google-{i}.cs";
            findings.Add(new Finding(
                ruleId,
                github ? "GitHub personal access token" : "Google API key",
                i + 1,
                i + 1,
                12,
                12 + secret.Length,
                $"token = \"{secret}\"",
                secret,
                file,
                string.Empty,
                string.Empty,
                4.2,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                github ? ["github", "token"] : ["gcp", "api-key"],
                $"{file}:{ruleId}:{i + 1}",
                $"token = \"{secret}\"",
                validationState: "structurally-valid"));
        }

        return findings;
    }

    private static string CreateGitHubToken(int index)
    {
        return string.Concat("ghp_", CreateAlphaNumericSuffix(index, 36));
    }

    private static string CreateGoogleApiKey(int index)
    {
        return string.Concat("AI", "za", CreateAlphaNumericSuffix(index, 35));
    }

    private static string CreateAlphaNumericSuffix(int index, int length)
    {
        const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return string.Create(length, index, static (chars, state) =>
        {
            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = Alphabet[(state + i) % Alphabet.Length];
            }
        });
    }
}
