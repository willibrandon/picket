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
    public IReadOnlyList<Finding> Scan(ScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        ReadOnlySpan<byte> input = request.Input.Span;
        var findings = new List<Finding>();

        foreach (SecretRule rule in request.RuleSet.Rules)
        {
            ByteRegex regex = ByteRegex.Compile(rule.Pattern);
            ScanRule(input, request.FileName, rule, regex, findings);
        }

        return findings;
    }

    private static void ScanRule(
        ReadOnlySpan<byte> input,
        string fileName,
        SecretRule rule,
        ByteRegex regex,
        List<Finding> findings)
    {
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
            SourcePosition start = SourcePosition.FromOffset(input, match.Start);
            SourcePosition end = SourcePosition.FromOffset(input, match.End);
            string matchText = DecodeReportText(match.Value(input));
            string secretText = DecodeReportText(secret.Value(input));

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
                ShannonEntropy.Calculate(secret.Value(input)),
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                rule.Tags,
                $"{fileName}:{rule.Id}:{start.Line}"));

            offset = AdvanceAfterMatch(match, input.Length);
        }
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
}
