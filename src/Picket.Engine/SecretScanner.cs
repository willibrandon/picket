using System.Text;
using Picket.Rules;
using Scout.Text.Regex;

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
            if (!IsPathCandidate(compiledRule, fileNameBytes, windowsFileNameBytes))
            {
                continue;
            }

            if (compiledRule.Regex is null)
            {
                if (!IsAllowed(
                    request.RuleSet.Allowlists,
                    compiledRule.Allowlists,
                    fileNameBytes,
                    windowsFileNameBytes,
                    [],
                    [],
                    [],
                    string.Empty,
                    string.Empty))
                {
                    findings.Add(CreatePathFinding(request.FileName, compiledRule.Rule));
                }

                continue;
            }

            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanRule(
                    input,
                    request.FileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    request.RuleSet.Allowlists,
                    compiledRule,
                    compiledRule.Regex,
                    findings);
            }
        }

        return findings;
    }

    private static void ScanRule(
        ReadOnlySpan<byte> input,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
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
                string.Empty))
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
                string.Empty,
                entropy,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                rule.Tags,
                $"{fileName}:{rule.Id}:{start.Line}"));

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

    private static Finding CreatePathFinding(string fileName, SecretRule rule)
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
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            rule.Tags,
            $"{fileName}:{rule.Id}:0");
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
        if (match.Length == 0)
        {
            return match.End < inputLength ? match.End + 1 : inputLength + 1;
        }

        return match.End;
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
