using BenchmarkDotNet.Attributes;
using Picket.Compat;
using Picket.Engine;
using Scout.Text.Regex;

namespace Picket.Benchmarks;

/// <summary>
/// Separates direct Scout regex execution from the surrounding Gitleaks-compatible scan pipeline.
/// </summary>
[BenchmarkCategory("GitleaksCompatibility", "Regex")]
[MemoryDiagnoser]
public class GitleaksRegexPipelineBenchmarks
{
    private int[] _candidateRuleIndexes = [];
    private byte[] _input = [];
    private CompiledRuleSet _rules = null!;

    /// <summary>
    /// Loads a representative repository input and eagerly compiles the compatibility rules.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        string repositoryRoot = FindRepositoryRoot();
        _input = File.ReadAllBytes(Path.Combine(
            repositoryRoot,
            "src",
            "Picket.Compat",
            "EmbeddedGitleaksConfig.cs"));
        _rules = CompiledRuleSet.Compile(
            GitleaksConfigLoader.LoadRuleSet(null, "__picket-regex-benchmark__"));
        _rules.PrepareForScanning();

        Span<bool> candidates = stackalloc bool[_rules.CompiledRules.Count];
        _rules.KeywordPrefilter.PopulateCandidates(_input, candidates);
        var candidateRuleIndexes = new List<int>();
        for (int ruleIndex = 0; ruleIndex < candidates.Length; ruleIndex++)
        {
            if (candidates[ruleIndex])
            {
                candidateRuleIndexes.Add(ruleIndex);
            }
        }

        _candidateRuleIndexes = [.. candidateRuleIndexes];
        int combinedMatchCount = ScoutRegexSearchOnly();
        int capturesOnlyMatchCount = ScoutRegexCapturesOnly();
        int findOnlyMatchCount = ScoutRegexFindOnly();
        int findThenCaptureMatchCount = ScoutRegexFindThenCaptures();
        if (capturesOnlyMatchCount != combinedMatchCount
            || findOnlyMatchCount != combinedMatchCount
            || findThenCaptureMatchCount != combinedMatchCount)
        {
            throw new InvalidOperationException(
                $"Regex execution variants returned {combinedMatchCount}, {capturesOnlyMatchCount}, "
                + $"{findOnlyMatchCount}, and {findThenCaptureMatchCount} matches.");
        }
    }

    /// <summary>
    /// Runs only the shared keyword candidate selection stage.
    /// </summary>
    /// <returns>The number of candidate rules.</returns>
    [Benchmark]
    public int KeywordCandidateSelectionOnly()
    {
        Span<bool> candidates = stackalloc bool[_rules.CompiledRules.Count];
        _rules.KeywordPrefilter.PopulateCandidates(_input, candidates);

        int candidateCount = 0;
        for (int ruleIndex = 0; ruleIndex < candidates.Length; ruleIndex++)
        {
            if (candidates[ruleIndex])
            {
                candidateCount++;
            }
        }

        return candidateCount;
    }

    /// <summary>
    /// Runs only candidate selection and Scout capture searches.
    /// </summary>
    /// <returns>The number of raw regex matches.</returns>
    [Benchmark(Baseline = true)]
    public int ScoutRegexSearchOnly()
    {
        int ruleCount = _rules.CompiledRules.Count;
        Span<bool> candidates = ruleCount <= 512
            ? stackalloc bool[ruleCount]
            : new bool[ruleCount];
        _rules.KeywordPrefilter.PopulateCandidates(_input, candidates);

        int matchCount = 0;
        for (int ruleIndex = 0; ruleIndex < ruleCount; ruleIndex++)
        {
            if (!candidates[ruleIndex])
            {
                continue;
            }

            ByteRegex? regex = _rules.CompiledRules[ruleIndex].Regex;
            if (regex is null)
            {
                continue;
            }

            int offset = 0;
            while (offset <= _input.Length)
            {
                ByteRegexCaptures? captures = regex.FindCaptures(_input, offset);
                if (captures is null)
                {
                    break;
                }

                ByteRegexMatch match = captures.Match;
                matchCount++;
                offset = match.Length == 0
                    ? (match.End < _input.Length ? match.End + 1 : _input.Length + 1)
                    : match.End;
            }
        }

        return matchCount;
    }

    /// <summary>
    /// Runs Scout capture searches over the candidate rules selected during setup.
    /// </summary>
    /// <returns>The number of raw regex matches.</returns>
    [Benchmark]
    public int ScoutRegexCapturesOnly()
    {
        int matchCount = 0;
        for (int candidateIndex = 0; candidateIndex < _candidateRuleIndexes.Length; candidateIndex++)
        {
            ByteRegex? regex = _rules.CompiledRules[_candidateRuleIndexes[candidateIndex]].Regex;
            if (regex is null)
            {
                continue;
            }

            int offset = 0;
            while (offset <= _input.Length)
            {
                ByteRegexCaptures? captures = regex.FindCaptures(_input, offset);
                if (captures is null)
                {
                    break;
                }

                ByteRegexMatch match = captures.Match;
                matchCount++;
                offset = match.Length == 0
                    ? (match.End < _input.Length ? match.End + 1 : _input.Length + 1)
                    : match.End;
            }
        }

        return matchCount;
    }

    /// <summary>
    /// Runs Scout match searches without capture extraction over the candidates selected during setup.
    /// </summary>
    /// <returns>The number of raw regex matches.</returns>
    [Benchmark]
    public int ScoutRegexFindOnly()
    {
        int matchCount = 0;
        for (int candidateIndex = 0; candidateIndex < _candidateRuleIndexes.Length; candidateIndex++)
        {
            ByteRegex? regex = _rules.CompiledRules[_candidateRuleIndexes[candidateIndex]].Regex;
            if (regex is null)
            {
                continue;
            }

            int offset = 0;
            while (offset <= _input.Length)
            {
                ByteRegexMatch? match = regex.Find(_input, offset);
                if (match is null)
                {
                    break;
                }

                matchCount++;
                offset = match.Value.Length == 0
                    ? (match.Value.End < _input.Length ? match.Value.End + 1 : _input.Length + 1)
                    : match.Value.End;
            }
        }

        return matchCount;
    }

    /// <summary>
    /// Finds each match without captures, then extracts captures from only the matched slice.
    /// </summary>
    /// <returns>The number of raw regex matches.</returns>
    [Benchmark]
    public int ScoutRegexFindThenCaptures()
    {
        int matchCount = 0;
        for (int candidateIndex = 0; candidateIndex < _candidateRuleIndexes.Length; candidateIndex++)
        {
            ByteRegex? regex = _rules.CompiledRules[_candidateRuleIndexes[candidateIndex]].Regex;
            if (regex is null)
            {
                continue;
            }

            int offset = 0;
            while (offset <= _input.Length)
            {
                ByteRegexMatch? match = regex.Find(_input, offset);
                if (match is null)
                {
                    break;
                }

                ReadOnlySpan<byte> matchBytes = match.Value.Value(_input);
                if (regex.FindCaptures(matchBytes, 0) is null)
                {
                    throw new InvalidOperationException("A matched slice did not reproduce its captures.");
                }

                matchCount++;
                offset = match.Value.Length == 0
                    ? (match.Value.End < _input.Length ? match.Value.End + 1 : _input.Length + 1)
                    : match.Value.End;
            }
        }

        return matchCount;
    }

    /// <summary>
    /// Runs the complete Gitleaks-compatible Picket matching pipeline over the same input.
    /// </summary>
    /// <returns>The number of retained findings.</returns>
    [Benchmark]
    public int PicketCompatibilityPipeline()
    {
        return SecretScanner.Scan(new ScanRequest(
            _input,
            "src/Picket.Compat/EmbeddedGitleaksConfig.cs",
            _rules,
            maxDecodeDepth: 0)).Count;
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
