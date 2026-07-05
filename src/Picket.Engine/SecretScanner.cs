using Picket.Rules;
using Scout.Text.Regex;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Byte-oriented secret scanner.
/// </summary>
public sealed class SecretScanner
{
    /// <summary>
    /// Scans a byte buffer and returns findings in rule evaluation order.
    /// </summary>
    public static IReadOnlyList<Finding> Scan(ScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        ReadOnlySpan<byte> input = request.Input.Span;
        byte[] fileNameBytes = Encoding.UTF8.GetBytes(request.FileName);
        byte[] windowsFileNameBytes = CreateWindowsFileNameBytes(request.FileName);
        var findings = new List<Finding>();

        foreach (CompiledRule compiledRule in request.RuleSet.CompiledRules)
        {
            List<Finding> ruleFindings = ScanCompiledRule(
                input,
                request.FileName,
                fileNameBytes,
                windowsFileNameBytes,
                request.RuleSet.Allowlists,
                request.IgnoreGitleaksAllow,
                request.Commit,
                compiledRule,
                includeSkipReport: false);
            if (compiledRule.Rule.RequiredRules.Count != 0)
            {
                ruleFindings = FilterRequiredFindings(
                    ruleFindings,
                    input,
                    request.FileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    request.RuleSet,
                    request.IgnoreGitleaksAllow,
                    request.Commit,
                    compiledRule);
            }

            findings.AddRange(ruleFindings);
        }

        return findings;
    }

    private static List<Finding> ScanCompiledRule(
        ReadOnlySpan<byte> input,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        CompiledRule compiledRule,
        bool includeSkipReport)
    {
        var findings = new List<Finding>();
        if (compiledRule.Rule.SkipReport && !includeSkipReport)
        {
            return findings;
        }

        if (!IsPathCandidate(compiledRule, fileNameBytes, windowsFileNameBytes))
        {
            return findings;
        }

        if (compiledRule.UsesGenericApiKeyMatcher)
        {
            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanGenericApiKeyRule(
                    input,
                    fileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    globalAllowlists,
                    ignoreGitleaksAllow,
                    commit,
                    compiledRule,
                    findings);
            }

            return findings;
        }

        if (!compiledRule.HasContentPattern)
        {
            if (!IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                [],
                [],
                [],
                string.Empty,
                commit))
            {
                findings.Add(CreatePathFinding(fileName, compiledRule.Rule, commit));
            }

            return findings;
        }

        if (compiledRule.Prefilter.IsCandidate(input))
        {
            ByteRegex regex = compiledRule.Regex ?? throw new InvalidOperationException("Content rule regex was not compiled.");
            ScanRule(
                input,
                fileName,
                fileNameBytes,
                windowsFileNameBytes,
                globalAllowlists,
                ignoreGitleaksAllow,
                commit,
                compiledRule,
                regex,
                findings);
        }

        return findings;
    }

    private static List<Finding> FilterRequiredFindings(
        List<Finding> primaryFindings,
        ReadOnlySpan<byte> input,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        CompiledRuleSet ruleSet,
        bool ignoreGitleaksAllow,
        string commit,
        CompiledRule primaryRule)
    {
        if (primaryFindings.Count == 0)
        {
            return primaryFindings;
        }

        var requiredFindingsByRuleId = new Dictionary<string, List<Finding>>(StringComparer.Ordinal);
        foreach (SecretRequiredRule requiredRule in primaryRule.Rule.RequiredRules)
        {
            if (requiredFindingsByRuleId.ContainsKey(requiredRule.Id))
            {
                continue;
            }

            CompiledRule? compiledRequiredRule = FindCompiledRule(ruleSet, requiredRule.Id);
            requiredFindingsByRuleId.Add(
                requiredRule.Id,
                compiledRequiredRule is null
                    ? []
                    : ScanCompiledRule(
                        input,
                        fileName,
                        fileNameBytes,
                        windowsFileNameBytes,
                        ruleSet.Allowlists,
                        ignoreGitleaksAllow,
                        commit,
                        compiledRequiredRule,
                        includeSkipReport: true));
        }

        var filteredFindings = new List<Finding>(primaryFindings.Count);
        foreach (Finding primaryFinding in primaryFindings)
        {
            if (HasAllRequiredRules(primaryFinding, primaryRule.Rule.RequiredRules, requiredFindingsByRuleId))
            {
                filteredFindings.Add(primaryFinding);
            }
        }

        return filteredFindings;
    }

    private static CompiledRule? FindCompiledRule(CompiledRuleSet ruleSet, string ruleId)
    {
        foreach (CompiledRule compiledRule in ruleSet.CompiledRules)
        {
            if (compiledRule.Rule.Id.Equals(ruleId, StringComparison.Ordinal))
            {
                return compiledRule;
            }
        }

        return null;
    }

    private static bool HasAllRequiredRules(
        Finding primaryFinding,
        IReadOnlyList<SecretRequiredRule> requiredRules,
        Dictionary<string, List<Finding>> requiredFindingsByRuleId)
    {
        var foundRuleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretRequiredRule requiredRule in requiredRules)
        {
            if (!requiredFindingsByRuleId.TryGetValue(requiredRule.Id, out List<Finding>? requiredFindings))
            {
                continue;
            }

            foreach (Finding requiredFinding in requiredFindings)
            {
                if (IsWithinProximity(primaryFinding, requiredFinding, requiredRule))
                {
                    foundRuleIds.Add(requiredRule.Id);
                    break;
                }
            }
        }

        if (foundRuleIds.Count == 0)
        {
            return false;
        }

        foreach (SecretRequiredRule requiredRule in requiredRules)
        {
            if (!foundRuleIds.Contains(requiredRule.Id))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsWithinProximity(Finding primaryFinding, Finding requiredFinding, SecretRequiredRule requiredRule)
    {
        if (requiredRule.WithinLines is null && requiredRule.WithinColumns is null)
        {
            return true;
        }

        if (requiredRule.WithinLines is int withinLines
            && Math.Abs(primaryFinding.StartLine - requiredFinding.StartLine) > withinLines)
        {
            return false;
        }

        return requiredRule.WithinColumns is not int withinColumns
            || Math.Abs(primaryFinding.StartColumn - requiredFinding.StartColumn) <= withinColumns;
    }

    private static void ScanGenericApiKeyRule(
        ReadOnlySpan<byte> input,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        CompiledRule compiledRule,
        List<Finding> findings)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (GenericApiKeyMatcher.TryFind(input, offset, out int matchStart, out int matchEnd, out int secretStart, out int secretEnd))
        {
            ReadOnlySpan<byte> secretBytes = input[secretStart..secretEnd];
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            SourcePosition start = SourcePosition.FromOffset(input, matchStart);
            SourcePosition end = SourcePosition.FromOffset(input, matchEnd);
            ReadOnlySpan<byte> matchBytes = input[matchStart..matchEnd];
            ReadOnlySpan<byte> lineBytes = ExtractLine(input, matchStart);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            string matchText = DecodeReportText(matchBytes);
            string secretText = DecodeReportText(secretBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                matchBytes,
                secretBytes,
                lineBytes,
                secretText,
                commit))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                secretText,
                fileName,
                string.Empty,
                commit,
                entropy,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                rule.Tags,
                CreateFingerprint(commit, fileName, rule.Id, start.Line)));

            offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
        }
    }

    private static void ScanRule(
        ReadOnlySpan<byte> input,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        CompiledRule compiledRule,
        ByteRegex regex,
        List<Finding> findings)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (offset <= input.Length)
        {
            ByteRegexCaptures? captures = regex.FindCaptures(input, offset);
            if (captures is null)
            {
                return;
            }

            ByteRegexMatch match = captures.Match;
            ByteRegexMatch secret = ResolveSecret(captures, rule.SecretGroup);
            ReadOnlySpan<byte> secretBytes = secret.Value(input);
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            SourcePosition start = SourcePosition.FromOffset(input, match.Start);
            SourcePosition end = SourcePosition.FromOffset(input, match.End);
            ReadOnlySpan<byte> matchBytes = match.Value(input);
            ReadOnlySpan<byte> lineBytes = ExtractLine(input, match.Start);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            string matchText = DecodeReportText(matchBytes);
            string secretText = DecodeReportText(secretBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                matchBytes,
                secretBytes,
                lineBytes,
                secretText,
                commit))
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                secretText,
                fileName,
                string.Empty,
                commit,
                entropy,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                rule.Tags,
                CreateFingerprint(commit, fileName, rule.Id, start.Line)));

            offset = AdvanceAfterMatch(match, input.Length);
        }
    }

    private static bool IsAllowed(
        List<CompiledAllowlist> globalAllowlists,
        List<CompiledAllowlist> ruleAllowlists,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        return IsAllowed(globalAllowlists, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit)
            || IsAllowed(ruleAllowlists, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit);
    }

    private static bool IsAllowed(
        List<CompiledAllowlist> allowlists,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        foreach (CompiledAllowlist allowlist in allowlists)
        {
            if (IsAllowed(allowlist, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAllowed(
        CompiledAllowlist compiledAllowlist,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        SecretAllowlist allowlist = compiledAllowlist.Allowlist;
        bool commitAllowed = IsCommitAllowed(allowlist, commit);
        bool pathAllowed = IsPathAllowed(compiledAllowlist, fileNameBytes, windowsFileNameBytes);
        bool regexAllowed = IsRegexAllowed(compiledAllowlist, allowlist.RegexTarget switch
        {
            AllowlistRegexTarget.Match => matchBytes,
            AllowlistRegexTarget.Line => lineBytes,
            _ => secretBytes,
        });
        bool stopWordAllowed = ContainsStopWord(allowlist, secretText);

        if (allowlist.Condition == AllowlistCondition.Or)
        {
            return commitAllowed || pathAllowed || regexAllowed || stopWordAllowed;
        }

        return IsConfiguredCheckAllowed(allowlist.Commits.Count, commitAllowed)
            && IsConfiguredCheckAllowed(allowlist.PathPatterns.Count, pathAllowed)
            && IsConfiguredCheckAllowed(allowlist.RegexPatterns.Count, regexAllowed)
            && IsConfiguredCheckAllowed(allowlist.StopWords.Count, stopWordAllowed);
    }

    private static bool IsConfiguredCheckAllowed(int count, bool isAllowed)
    {
        return count == 0 || isAllowed;
    }

    private static bool IsCommitAllowed(SecretAllowlist allowlist, string commit)
    {
        return commit.Length != 0
            && allowlist.Commits.Contains(commit.ToLowerInvariant(), StringComparer.Ordinal);
    }

    private static bool IsPathAllowed(
        CompiledAllowlist allowlist,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes)
    {
        return AnyRegexMatches(allowlist.PathRegexes, fileNameBytes)
            || (!windowsFileNameBytes.IsEmpty && AnyRegexMatches(allowlist.PathRegexes, windowsFileNameBytes));
    }

    private static bool IsRegexAllowed(CompiledAllowlist allowlist, ReadOnlySpan<byte> target)
    {
        return !target.IsEmpty && AnyRegexMatches(allowlist.Regexes, target);
    }

    private static bool AnyRegexMatches(List<ByteRegex> regexes, ReadOnlySpan<byte> input)
    {
        foreach (ByteRegex regex in regexes)
        {
            if (regex.FindCaptures(input, 0) is not null)
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsStopWord(SecretAllowlist allowlist, string secretText)
    {
        if (secretText.Length == 0)
        {
            return false;
        }

        foreach (string stopWord in allowlist.StopWords)
        {
            if (secretText.Contains(stopWord, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsGitleaksAllow(ReadOnlySpan<byte> lineBytes)
    {
        return lineBytes.IndexOf("gitleaks:allow"u8) >= 0;
    }

    private static bool IsPathCandidate(CompiledRule compiledRule, ReadOnlySpan<byte> fileNameBytes, ReadOnlySpan<byte> windowsFileNameBytes)
    {
        if (compiledRule.PathRegex is null)
        {
            return true;
        }

        if (compiledRule.PathRegex.FindCaptures(fileNameBytes, 0) is not null)
        {
            return true;
        }

        return !windowsFileNameBytes.IsEmpty
            && compiledRule.PathRegex.FindCaptures(windowsFileNameBytes, 0) is not null;
    }

    private static Finding CreatePathFinding(string fileName, SecretRule rule, string commit)
    {
        return new Finding(
            rule.Id,
            rule.Description,
            0,
            0,
            0,
            0,
            $"file detected: {fileName}",
            string.Empty,
            fileName,
            string.Empty,
            commit,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            rule.Tags,
            CreateFingerprint(commit, fileName, rule.Id, 0));
    }

    private static string CreateFingerprint(string commit, string fileName, string ruleId, int startLine)
    {
        return commit.Length == 0
            ? $"{fileName}:{ruleId}:{startLine}"
            : $"{commit}:{fileName}:{ruleId}:{startLine}";
    }

    private static ByteRegexMatch ResolveSecret(ByteRegexCaptures captures, int secretGroup)
    {
        if (secretGroup > 0)
        {
            ByteRegexMatch? group = captures.GetGroup(secretGroup);
            return group ?? captures.Match;
        }

        for (int groupIndex = 1; groupIndex < captures.GroupCount; groupIndex++)
        {
            ByteRegexMatch? group = captures.GetGroup(groupIndex);
            if (group is { Length: > 0 })
            {
                return group.Value;
            }
        }

        return captures.Match;
    }

    private static int AdvanceAfterMatch(ByteRegexMatch match, int inputLength)
    {
        return AdvanceAfterMatch(match.Start, match.End, inputLength);
    }

    private static int AdvanceAfterMatch(int matchStart, int matchEnd, int inputLength)
    {
        if (matchEnd == matchStart)
        {
            return matchEnd < inputLength ? matchEnd + 1 : inputLength + 1;
        }

        return matchEnd;
    }

    private static string DecodeReportText(ReadOnlySpan<byte> bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }

    private static ReadOnlySpan<byte> ExtractLine(ReadOnlySpan<byte> input, int offset)
    {
        int start = offset;
        while (start > 0 && input[start - 1] is not ((byte)'\n' or (byte)'\r'))
        {
            start--;
        }

        int end = offset;
        while (end < input.Length && input[end] is not ((byte)'\n' or (byte)'\r'))
        {
            end++;
        }

        return input[start..end];
    }

    private static byte[] CreateWindowsFileNameBytes(string fileName)
    {
        return fileName.Contains('/')
            ? Encoding.UTF8.GetBytes(fileName.Replace('/', '\\'))
            : [];
    }
}
