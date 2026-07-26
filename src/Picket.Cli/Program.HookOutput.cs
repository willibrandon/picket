using Picket.Engine;
using System.Globalization;
using System.Text;

namespace Picket;

internal static partial class Program
{
    private const int HookFindingExitCode = 3;
    private const int MaxHookCommitLength = 12;
    private const int MaxHookPathLength = 512;
    private const int MaxHookRuleIdLength = 120;
    private const int MaxHookSummaryFindings = 20;
    private const string HookRedactedValue = "REDACTED";
    private const string PreCommitHookContext = "pre-commit";
    private const string PrePushHookContext = "pre-push";
    private const string PreReceiveHookContext = "pre-receive";

    static bool TryReadHookContext(string[] args, ref int index, out string? hookContext)
    {
        if (!TryReadStringFlag(args, ref index, "--hook-context", out string? value))
        {
            hookContext = null;
            return false;
        }

        hookContext = value.ToLowerInvariant();
        if (hookContext is PreCommitHookContext or PrePushHookContext or PreReceiveHookContext)
        {
            return true;
        }

        Console.Error.WriteLine($"unsupported hook context: {value}");
        hookContext = null;
        return false;
    }

    static void WriteHookFindingSummary(TextWriter writer, IReadOnlyList<Finding> findings, string hookContext)
    {
        int findingCount = findings.Count;
        string findingLabel = findingCount == 1 ? "finding" : "findings";
        writer.WriteLine();
        writer.WriteLine(hookContext switch
        {
            PreCommitHookContext => $"Picket blocked the commit: {findingCount.ToString(CultureInfo.InvariantCulture)} {findingLabel} in staged changes.",
            PrePushHookContext => $"Picket blocked the push: {findingCount.ToString(CultureInfo.InvariantCulture)} {findingLabel} in outgoing commits.",
            PreReceiveHookContext => $"Picket rejected the push: {findingCount.ToString(CultureInfo.InvariantCulture)} {findingLabel} in received commits.",
            _ => throw new InvalidOperationException($"unsupported hook context: {hookContext}"),
        });

        int displayedFindingCount = Math.Min(findingCount, MaxHookSummaryFindings);
        for (int i = 0; i < displayedFindingCount; i++)
        {
            Finding finding = findings[i];
            string ruleId = SanitizeHookFindingText(finding.RuleID, finding, MaxHookRuleIdLength);
            string path = finding.File.Length == 0
                ? "(unknown path)"
                : SanitizeHookFindingText(finding.File, finding, MaxHookPathLength);
            writer.Write("  ");
            writer.Write(ruleId);
            writer.Write("  ");
            writer.Write(path);
            writer.Write(':');
            writer.Write(finding.StartLine.ToString(CultureInfo.InvariantCulture));
            if (hookContext is not PreCommitHookContext && finding.Commit.Length != 0)
            {
                writer.Write("  commit ");
                writer.Write(SanitizeHookFindingText(finding.Commit, finding, MaxHookCommitLength));
            }

            writer.WriteLine();
        }

        int undisplayedFindingCount = findingCount - displayedFindingCount;
        if (undisplayedFindingCount != 0)
        {
            writer.WriteLine($"  ... {undisplayedFindingCount.ToString(CultureInfo.InvariantCulture)} more findings");
        }

        writer.WriteLine("Secret values are not printed.");
        writer.WriteLine(hookContext switch
        {
            PreCommitHookContext => "Resolve the findings or allowlist expected values, then retry the commit.",
            PrePushHookContext => "Resolve the findings in the outgoing commits or allowlist expected values, then retry the push.",
            PreReceiveHookContext => "Resolve the findings in the pushed commits or ask a repository administrator to allowlist expected values, then retry.",
            _ => throw new InvalidOperationException($"unsupported hook context: {hookContext}"),
        });
    }

    static string SanitizeHookFindingText(string value, Finding finding, int maxLength)
    {
        string redacted = RedactHookFindingText(value, finding.Secret);
        redacted = RedactHookFindingText(redacted, finding.Match);
        redacted = RedactHookFindingText(redacted, finding.Line);
        return SanitizeHookText(redacted, maxLength);
    }

    static string RedactHookFindingText(string value, string sensitiveValue)
    {
        return sensitiveValue.Length == 0
            ? value
            : value.Replace(sensitiveValue, HookRedactedValue, StringComparison.Ordinal);
    }

    static string SanitizeHookText(string value, int maxLength)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maxLength));
        int runeCount = 0;
        bool truncated = false;
        foreach (Rune rune in value.EnumerateRunes())
        {
            if (runeCount == maxLength)
            {
                truncated = true;
                break;
            }

            UnicodeCategory category = Rune.GetUnicodeCategory(rune);
            builder.Append(category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator
                    ? '?'
                    : rune.ToString());
            runeCount++;
        }

        if (truncated)
        {
            builder.Append("...");
        }

        return builder.ToString();
    }
}
