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
                findings.Add(CreatePathFinding(request.FileName, compiledRule.Rule));
                continue;
            }

            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanRule(input, request.FileName, compiledRule, compiledRule.Regex, findings);
            }
        }

        return findings;
    }

    private static void ScanRule(
        ReadOnlySpan<byte> input,
        string fileName,
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
            string matchText = DecodeReportText(match.Value(input));
            string secretText = DecodeReportText(secretBytes);

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
        if (secretGroup == 0)
        {
            return captures.Match;
        }

        ByteRegexMatch? group = captures.GetGroup(secretGroup);
        return group ?? captures.Match;
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

    private static byte[] CreateWindowsFileNameBytes(string fileName)
    {
        return fileName.Contains('/')
            ? Encoding.UTF8.GetBytes(fileName.Replace('/', '\\'))
            : [];
    }
}
