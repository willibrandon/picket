using Picket.Rules;
using Scout;
using System.Text;

namespace Picket.Engine;

internal sealed class KeywordPrefilter
{
    private readonly AhoCorasickAutomaton? _asciiAutomaton;
    private readonly int[][] _asciiRuleIndexes;
    private readonly int[] _rulesWithoutKeywords;
    private readonly AhoCorasickAutomaton? _unicodeAutomaton;
    private readonly int[][] _unicodeRuleIndexes;

    private KeywordPrefilter(
        AhoCorasickAutomaton? asciiAutomaton,
        int[][] asciiRuleIndexes,
        AhoCorasickAutomaton? unicodeAutomaton,
        int[][] unicodeRuleIndexes,
        int[] rulesWithoutKeywords)
    {
        _asciiAutomaton = asciiAutomaton;
        _asciiRuleIndexes = asciiRuleIndexes;
        _unicodeAutomaton = unicodeAutomaton;
        _unicodeRuleIndexes = unicodeRuleIndexes;
        _rulesWithoutKeywords = rulesWithoutKeywords;
    }

    internal static KeywordPrefilter Create(IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var asciiMappings = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var unicodeMappings = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var rulesWithoutKeywords = new List<int>();
        for (int ruleIndex = 0; ruleIndex < rules.Count; ruleIndex++)
        {
            IReadOnlyList<string> keywords = rules[ruleIndex].Keywords;
            bool hasKeyword = false;
            for (int keywordIndex = 0; keywordIndex < keywords.Count; keywordIndex++)
            {
                string keyword = keywords[keywordIndex];
                if (string.IsNullOrEmpty(keyword))
                {
                    continue;
                }

                hasKeyword = true;
                string normalizedKeyword = keyword.ToLowerInvariant();
                Dictionary<string, List<int>> mappings = IsAscii(keyword)
                    ? asciiMappings
                    : unicodeMappings;
                AddRuleMapping(mappings, normalizedKeyword, ruleIndex);
            }

            if (!hasKeyword)
            {
                rulesWithoutKeywords.Add(ruleIndex);
            }
        }

        AhoCorasickAutomaton? asciiAutomaton = BuildAutomaton(
            asciiMappings,
            asciiCaseInsensitive: true,
            out int[][] asciiRuleIndexes);
        AhoCorasickAutomaton? unicodeAutomaton = BuildAutomaton(
            unicodeMappings,
            asciiCaseInsensitive: false,
            out int[][] unicodeRuleIndexes);
        return new KeywordPrefilter(
            asciiAutomaton,
            asciiRuleIndexes,
            unicodeAutomaton,
            unicodeRuleIndexes,
            [.. rulesWithoutKeywords]);
    }

    internal void PopulateCandidates(
        ReadOnlySpan<byte> input,
        Span<bool> candidates)
    {
        candidates.Clear();
        for (int index = 0; index < _rulesWithoutKeywords.Length; index++)
        {
            candidates[_rulesWithoutKeywords[index]] = true;
        }

        PopulateMatches(_asciiAutomaton, _asciiRuleIndexes, input, candidates);
        if (_unicodeAutomaton is null)
        {
            return;
        }

        string normalizedInput = Encoding.UTF8.GetString(input).ToLowerInvariant();
        int byteCount = Encoding.UTF8.GetByteCount(normalizedInput);
        byte[] normalizedBytes = GC.AllocateUninitializedArray<byte>(byteCount);
        Encoding.UTF8.GetBytes(normalizedInput, normalizedBytes);
        PopulateMatches(_unicodeAutomaton, _unicodeRuleIndexes, normalizedBytes, candidates);
    }

    private static void AddRuleMapping(
        Dictionary<string, List<int>> mappings,
        string keyword,
        int ruleIndex)
    {
        if (!mappings.TryGetValue(keyword, out List<int>? ruleIndexes))
        {
            ruleIndexes = [];
            mappings.Add(keyword, ruleIndexes);
        }

        if (ruleIndexes.Count == 0 || ruleIndexes[^1] != ruleIndex)
        {
            ruleIndexes.Add(ruleIndex);
        }
    }

    private static AhoCorasickAutomaton? BuildAutomaton(
        Dictionary<string, List<int>> mappings,
        bool asciiCaseInsensitive,
        out int[][] ruleIndexes)
    {
        if (mappings.Count == 0)
        {
            ruleIndexes = [];
            return null;
        }

        var patterns = new List<byte[]>(mappings.Count);
        ruleIndexes = new int[mappings.Count][];
        int patternIndex = 0;
        foreach ((string keyword, List<int> mappedRuleIndexes) in mappings)
        {
            patterns.Add(Encoding.UTF8.GetBytes(keyword));
            ruleIndexes[patternIndex] = [.. mappedRuleIndexes];
            patternIndex++;
        }

        return AhoCorasickAutomaton.Create(
            patterns,
            AhoCorasickMatchKind.Standard,
            asciiCaseInsensitive);
    }

    private static void PopulateMatches(
        AhoCorasickAutomaton? automaton,
        int[][] ruleIndexes,
        ReadOnlySpan<byte> input,
        Span<bool> candidates)
    {
        if (automaton is null)
        {
            return;
        }

        AhoCorasickOverlappingEnumerator enumerator = automaton.EnumerateOverlapping(input);
        while (enumerator.MoveNext())
        {
            int[] matchingRuleIndexes = ruleIndexes[enumerator.Current.PatternId];
            for (int index = 0; index < matchingRuleIndexes.Length; index++)
            {
                candidates[matchingRuleIndexes[index]] = true;
            }
        }
    }

    private static bool IsAscii(string value)
    {
        foreach (char character in value)
        {
            if (!char.IsAscii(character))
            {
                return false;
            }
        }

        return true;
    }
}
