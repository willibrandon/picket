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
            builder.ToString());
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
        builder.AppendLine("| Rule | Provider | Severity | Confidence | Validation | Revocation | Tags | Examples |");
        builder.AppendLine("|---|---|---|---|---|---|---|---:|");
        foreach (SecretRule rule in rules)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(rule.Id));
            builder.Append("`<br />");
            builder.Append(EscapeTable(rule.Description));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatOptionalValue(rule.Provider)));
            builder.Append(" | ");
            builder.Append(EscapeTable(rule.Severity));
            builder.Append(" | ");
            builder.Append(EscapeTable(rule.Confidence));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rule.Validation)));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rule.Revocation)));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rule.Tags)));
            builder.Append(" | ");
            builder.Append(FormatExampleCounts(rule));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
    }

    private static void AppendCompatibilityRuleCatalog(StringBuilder builder, List<SecretRule> rules)
    {
        builder.AppendLine("## Gitleaks-Compatible Rules");
        builder.AppendLine();
        builder.AppendLine("| Rule | Tags | Keywords | Entropy | Secret group | Allowlists |");
        builder.AppendLine("|---|---|---|---:|---:|---:|");
        foreach (SecretRule rule in rules)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(rule.Id));
            builder.Append("`<br />");
            builder.Append(EscapeTable(rule.Description));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rule.Tags)));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rule.Keywords)));
            builder.Append(" | ");
            builder.Append(rule.Entropy.ToString("0.###", CultureInfo.InvariantCulture));
            builder.Append(" | ");
            builder.Append(rule.SecretGroup.ToString(CultureInfo.InvariantCulture));
            builder.Append(" | ");
            builder.Append(rule.Allowlists.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
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
