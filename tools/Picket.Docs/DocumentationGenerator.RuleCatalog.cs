using Picket.Compat;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    private static void GenerateRuleCatalogReference(string outputRoot)
    {
        RuleSet gitleaksRules = GitleaksConfigLoader.LoadDefaultRuleSet();
        RuleSet picketRules = PicketConfigLoader.LoadDefaultRuleSet();
        var gitleaksRuleIds = new HashSet<string>(
            gitleaksRules.Rules.Select(static rule => rule.Id),
            StringComparer.Ordinal);
        List<SecretRule> nativeRules = [.. picketRules.Rules
            .Where(rule => IsNativePicketRule(rule, gitleaksRuleIds))
            .OrderBy(static rule => rule.Provider, StringComparer.Ordinal)
            .ThenBy(static rule => rule.Id, StringComparer.Ordinal)];
        List<SecretRule> compatibilityRules = [.. gitleaksRules.Rules.OrderBy(static rule => rule.Id, StringComparer.Ordinal)];

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from embedded default rule sets through `GitleaksConfigLoader.LoadDefaultRuleSet()` and `PicketConfigLoader.LoadDefaultRuleSet()`.");
        builder.AppendLine();
        builder.AppendLine("Positive and negative example values are intentionally summarized as counts rather than printed.");
        builder.AppendLine();
        AppendRuleCatalogSummary(builder, compatibilityRules, nativeRules);
        AppendNativeRuleCatalog(builder, nativeRules);
        AppendCompatibilityRuleCatalog(builder, compatibilityRules);

        WriteMarkdown(
            Path.Combine(outputRoot, "rule-catalog.md"),
            "Rule Catalog",
            "Generated catalog for embedded Gitleaks-compatible and Picket-native rule packs.",
            builder.ToString(),
            tableOfContents: false);
    }

    private static bool IsNativePicketRule(SecretRule rule, HashSet<string> gitleaksRuleIds)
    {
        return rule.RulePack.Equals("picket-default", StringComparison.Ordinal)
            || rule.Id.StartsWith("picket-", StringComparison.Ordinal)
            || !gitleaksRuleIds.Contains(rule.Id);
    }

    private static void AppendRuleCatalogSummary(
        StringBuilder builder,
        List<SecretRule> compatibilityRules,
        List<SecretRule> nativeRules)
    {
        builder.AppendLine("## Summary");
        builder.AppendLine();
        builder.AppendLine("| Catalog | Rules | Notes |");
        builder.AppendLine("|---|---:|---|");
        builder.Append("| Gitleaks-compatible default | ");
        builder.Append(compatibilityRules.Count.ToString(CultureInfo.InvariantCulture));
        builder.AppendLine(" | Embedded strict-compatibility rules used by Gitleaks-compatible commands. |");
        builder.Append("| Picket-native additions | ");
        builder.Append(nativeRules.Count.ToString(CultureInfo.InvariantCulture));
        builder.AppendLine(" | Native rules layered by the `picket-default` rule pack. |");
        builder.AppendLine();

        AppendRuleMetadataSet(builder, "Native providers", nativeRules.Select(static rule => rule.Provider));
        AppendRuleMetadataSet(builder, "Native validation templates", nativeRules.SelectMany(static rule => rule.Validation));
        AppendRuleMetadataSet(builder, "Native revocation templates", nativeRules.SelectMany(static rule => rule.Revocation));
    }

    private static void AppendRuleMetadataSet(StringBuilder builder, string title, IEnumerable<string> values)
    {
        string[] normalized = [.. values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        builder.Append("**");
        builder.Append(EscapeMarkdownText(title));
        builder.AppendLine("**");
        builder.AppendLine();
        builder.AppendLine(FormatValueList(normalized));
        builder.AppendLine();
    }

    private static void AppendNativeRuleCatalog(StringBuilder builder, List<SecretRule> rules)
    {
        builder.AppendLine("## Picket-Native Rules");
        builder.AppendLine();
        builder.AppendLine("<div class=\"reference-summary-list\">");
        foreach (SecretRule rule in rules)
        {
            AppendNativeRuleSummary(builder, rule);
        }

        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendCompatibilityRuleCatalog(StringBuilder builder, List<SecretRule> rules)
    {
        builder.AppendLine("## Gitleaks-Compatible Rules");
        builder.AppendLine();
        builder.AppendLine("<div class=\"reference-summary-list\">");
        foreach (SecretRule rule in rules)
        {
            AppendCompatibilityRuleSummary(builder, rule);
        }

        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendNativeRuleSummary(StringBuilder builder, SecretRule rule)
    {
        AppendRuleSummaryHeader(builder, rule.Id, FormatOptionalValue(rule.Provider), rule.Description);
        builder.Append("    <p class=\"reference-summary-meta\"><span>Severity <code>");
        builder.Append(EscapeHtmlCode(rule.Severity));
        builder.Append("</code></span><span>Confidence <code>");
        builder.Append(EscapeHtmlCode(rule.Confidence));
        builder.Append("</code></span><span>Examples ");
        builder.Append(EscapeHtmlText(FormatExampleCounts(rule)));
        builder.AppendLine("</span></p>");
        AppendRuleSummaryDetail(builder, "Validation", FormatValueList(rule.Validation));
        AppendRuleSummaryDetail(builder, "Revocation", FormatValueList(rule.Revocation));
        AppendRuleSummaryDetail(builder, "Tags", FormatValueList(rule.Tags));
        builder.AppendLine("  </article>");
    }

    private static void AppendCompatibilityRuleSummary(StringBuilder builder, SecretRule rule)
    {
        AppendRuleSummaryHeader(builder, rule.Id, "Gitleaks-compatible", rule.Description);
        builder.Append("    <p class=\"reference-summary-meta\"><span>Entropy ");
        builder.Append(EscapeHtmlText(rule.Entropy.ToString("0.###", CultureInfo.InvariantCulture)));
        builder.Append("</span><span>Secret group ");
        builder.Append(EscapeHtmlText(rule.SecretGroup.ToString(CultureInfo.InvariantCulture)));
        builder.Append("</span><span>Allowlists ");
        builder.Append(EscapeHtmlText(rule.Allowlists.Count.ToString(CultureInfo.InvariantCulture)));
        builder.AppendLine("</span></p>");
        AppendRuleSummaryDetail(builder, "Tags", FormatValueList(rule.Tags));
        AppendRuleSummaryDetail(builder, "Keywords", FormatValueList(rule.Keywords));
        builder.AppendLine("  </article>");
    }

    private static void AppendRuleSummaryHeader(
        StringBuilder builder,
        string title,
        string subtitle,
        string description)
    {
        builder.AppendLine("  <article class=\"reference-summary-card\">");
        builder.AppendLine("    <div class=\"reference-summary-heading\">");
        builder.Append("      <code>");
        builder.Append(EscapeHtmlCode(title));
        builder.Append("</code><span>");
        builder.Append(EscapeHtmlText(subtitle));
        builder.AppendLine("</span>");
        builder.AppendLine("    </div>");
        if (!string.IsNullOrWhiteSpace(description))
        {
            builder.Append("    <p class=\"reference-summary-description\">");
            builder.Append(EscapeHtmlText(description));
            builder.AppendLine("</p>");
        }
    }

    private static void AppendRuleSummaryDetail(StringBuilder builder, string label, string value)
    {
        builder.Append("    <p class=\"reference-summary-detail\"><strong>");
        builder.Append(EscapeHtmlText(label));
        builder.Append("</strong>: ");
        builder.Append(EscapeHtmlText(value));
        builder.AppendLine("</p>");
    }

    private static string FormatValueList(IEnumerable<string> values)
    {
        string[] normalized = [.. values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Order(StringComparer.Ordinal)];

        return normalized.Length == 0
            ? "-"
            : string.Join(", ", normalized);
    }

    private static string FormatOptionalValue(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "-" : value;
    }

    private static string FormatExampleCounts(SecretRule rule)
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{rule.Examples.Count}/{rule.NegativeExamples.Count}");
    }
}
