using Picket.Analyze;
using Picket.Engine;
using Picket.Rules;
using Picket.Verify;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    private static readonly string[] s_analysisRuleIds =
    [
        "picket-aws-access-key-pair",
        "picket-azure-storage-connection-string",
        "picket-database-connection-url",
        "picket-gcp-service-account-key",
        "picket-google-api-key",
        "picket-github-personal-access-token",
        "gitlab-pat",
        "picket-sourcegraph-access-token",
        "private-key",
        "example-unknown-rule",
    ];

    private static void GenerateValidationAnalyzeReference(string outputRoot)
    {
        List<SecretRule> nativeRules = GetNativeRules();
        List<CredentialAnalysis> analyses = CreateSampleAnalyses();

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from `SecretValidationState`, `SecretValidationResult`, embedded native rule metadata, and `CredentialAnalyzer` output. Values are structural contract data, not live provider responses.");
        builder.AppendLine();
        AppendValidationStates(builder);
        AppendValidationTemplateReference(builder, nativeRules);
        AppendRevocationTemplateReference(builder, nativeRules);
        AppendSeverityConfidenceTable(builder, nativeRules);
        AppendAnalysisRiskTable(builder);
        AppendProviderAnalysisTable(builder, analyses);
        AppendAnalysisSchema(builder, analyses);

        WriteMarkdown(
            Path.Combine(outputRoot, "validation-analyze.md"),
            "Validation and Analyze Reference",
            "Generated reference for validation states, rule metadata, and credential analysis output.",
            builder.ToString(),
            tableOfContents: false);
    }

    private static List<SecretRule> GetNativeRules()
    {
        return GetBuiltInNativeRules();
    }

    private static void AppendValidationStates(StringBuilder builder)
    {
        builder.AppendLine("## Validation States");
        builder.AppendLine();
        builder.AppendLine("| State | Report value | Meaning |");
        builder.AppendLine("|---|---|---|");
        foreach (SecretValidationState state in Enum.GetValues<SecretValidationState>())
        {
            builder.Append("| `");
            builder.Append(state);
            builder.Append("` | `");
            builder.Append(EscapeTable(SecretValidationResult.ToReportValue(state)));
            builder.Append("` | ");
            builder.Append(EscapeTable(GetValidationStateMeaning(state)));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
    }

    private static string GetValidationStateMeaning(SecretValidationState state)
    {
        return state switch
        {
            SecretValidationState.Unknown => "No offline or live validator produced a provider-specific verdict.",
            SecretValidationState.StructurallyValid => "Offline validation matched a known provider structure, checksum, or envelope.",
            SecretValidationState.TestCredential => "Offline validation identified a dummy, placeholder, sample, or test credential.",
            SecretValidationState.Invalid => "Offline validation rejected the provider structure or checksum.",
            SecretValidationState.Active => "Live provider verification proved that the credential is active.",
            SecretValidationState.Inactive => "Live provider verification proved that the credential is inactive or revoked.",
            SecretValidationState.Skipped => "Live provider verification intentionally skipped the finding.",
            SecretValidationState.Error => "Live provider verification ended in a provider, network, policy, or rate-limit error.",
            _ => "Unknown validation state.",
        };
    }

    private static void AppendValidationTemplateReference(StringBuilder builder, List<SecretRule> nativeRules)
    {
        builder.AppendLine("## Validation Templates");
        builder.AppendLine();
        AppendTemplateReferenceList(
            builder,
            CreateTemplateSummaries(nativeRules, static rule => rule.Validation));
    }

    private static void AppendRevocationTemplateReference(StringBuilder builder, List<SecretRule> nativeRules)
    {
        builder.AppendLine("## Revocation Templates");
        builder.AppendLine();
        AppendTemplateReferenceList(
            builder,
            CreateTemplateSummaries(nativeRules, static rule => rule.Revocation));
    }

    private static List<(string Template, string Kind, string Providers, int RuleCount, string RuleIds)> CreateTemplateSummaries(
        List<SecretRule> rules,
        Func<SecretRule, IReadOnlyList<string>> selector)
    {
        var templateRules = new SortedDictionary<string, List<SecretRule>>(StringComparer.Ordinal);
        for (int i = 0; i < rules.Count; i++)
        {
            SecretRule rule = rules[i];
            IReadOnlyList<string> templates = selector(rule);
            for (int j = 0; j < templates.Count; j++)
            {
                string template = templates[j];
                if (string.IsNullOrWhiteSpace(template))
                {
                    continue;
                }

                if (!templateRules.TryGetValue(template, out List<SecretRule>? groupedRules))
                {
                    groupedRules = [];
                    templateRules.Add(template, groupedRules);
                }

                groupedRules.Add(rule);
            }
        }

        var summaries = new List<(string Template, string Kind, string Providers, int RuleCount, string RuleIds)>(templateRules.Count);
        foreach ((string template, List<SecretRule> groupedRules) in templateRules)
        {
            summaries.Add((
                template,
                GetTemplateKind(template),
                FormatValueList(groupedRules.Select(static rule => rule.Provider).Distinct(StringComparer.Ordinal)),
                groupedRules.Count,
                FormatValueList(groupedRules.Select(static rule => rule.Id).Distinct(StringComparer.Ordinal))));
        }

        return summaries;
    }

    private static void AppendTemplateReferenceList(
        StringBuilder builder,
        List<(string Template, string Kind, string Providers, int RuleCount, string RuleIds)> templates)
    {
        builder.AppendLine("<div class=\"reference-summary-list\">");
        foreach ((string template, string kind, string providers, int ruleCount, string ruleIds) in templates)
        {
            builder.AppendLine("  <article class=\"reference-summary-card\">");
            builder.AppendLine("    <div class=\"reference-summary-heading\">");
            builder.Append("      <code>");
            builder.Append(EscapeHtmlCode(template));
            builder.Append("</code><span>");
            builder.Append(EscapeHtmlText(kind));
            builder.AppendLine("</span>");
            builder.AppendLine("    </div>");
            builder.Append("    <p class=\"reference-summary-meta\"><span>");
            builder.Append(EscapeHtmlText(providers.Length == 0 ? "-" : providers));
            builder.Append("</span><span>");
            builder.Append(ruleCount.ToString(CultureInfo.InvariantCulture));
            builder.Append(ruleCount == 1 ? " rule" : " rules");
            builder.AppendLine("</span></p>");
            builder.Append("    <p class=\"reference-summary-detail\">");
            builder.Append(EscapeHtmlText(ruleIds.Length == 0 ? "-" : ruleIds));
            builder.AppendLine("</p>");
            builder.AppendLine("  </article>");
        }

        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static string GetTemplateKind(string template)
    {
        if (template.StartsWith("offline:", StringComparison.Ordinal))
        {
            return "Offline structural validation";
        }

        if (template.StartsWith("live:", StringComparison.Ordinal))
        {
            return "Live provider verification";
        }

        if (template.StartsWith("revocation:", StringComparison.Ordinal))
        {
            return "Provider revocation guidance";
        }

        return "Provider metadata";
    }

    private static void AppendSeverityConfidenceTable(StringBuilder builder, List<SecretRule> nativeRules)
    {
        builder.AppendLine("## Severity and Confidence");
        builder.AppendLine();
        builder.AppendLine("| Severity | Confidence | Rules | Providers |");
        builder.AppendLine("|---|---|---:|---|");
        IEnumerable<IGrouping<(string Severity, string Confidence), SecretRule>> groups = nativeRules
            .GroupBy(static rule => (rule.Severity, rule.Confidence))
            .OrderBy(static group => group.Key.Severity, StringComparer.Ordinal)
            .ThenBy(static group => group.Key.Confidence, StringComparer.Ordinal);
        foreach (IGrouping<(string Severity, string Confidence), SecretRule> group in groups)
        {
            List<SecretRule> rules = [.. group];
            builder.Append("| `");
            builder.Append(EscapeTable(group.Key.Severity));
            builder.Append("` | `");
            builder.Append(EscapeTable(group.Key.Confidence));
            builder.Append("` | ");
            builder.Append(rules.Count.ToString(CultureInfo.InvariantCulture));
            builder.Append(" | ");
            builder.Append(EscapeTable(FormatValueList(rules.Select(static rule => rule.Provider).Distinct(StringComparer.Ordinal))));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
    }

    private static void AppendAnalysisRiskTable(StringBuilder builder)
    {
        builder.AppendLine("## Analyze Risk Mapping");
        builder.AppendLine();
        builder.AppendLine("| Validation state | Risk | Identity fallback | Metadata fallback |");
        builder.AppendLine("|---|---|---|---|");
        foreach (SecretValidationState state in Enum.GetValues<SecretValidationState>())
        {
            string reportValue = SecretValidationResult.ToReportValue(state);
            CredentialAnalysis analysis = CredentialAnalyzer.Analyze(CreateAnalysisFinding(
                "picket-github-personal-access-token",
                reportValue,
                "src/generated-reference.cs",
                line: 10));

            builder.Append("| `");
            builder.Append(EscapeTable(reportValue));
            builder.Append("` | `");
            builder.Append(EscapeTable(analysis.Risk));
            builder.Append("` | `");
            builder.Append(EscapeTable(analysis.Identity));
            builder.Append("` | `");
            builder.Append(EscapeTable(FormatValueList(analysis.Scopes)));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendProviderAnalysisTable(StringBuilder builder, List<CredentialAnalysis> analyses)
    {
        builder.AppendLine("## Provider Analysis Metadata");
        builder.AppendLine();
        builder.AppendLine("<div class=\"reference-summary-list\">");
        foreach (CredentialAnalysis analysis in analyses
            .OrderBy(static value => value.Provider, StringComparer.Ordinal)
            .ThenBy(static value => value.CredentialType, StringComparer.Ordinal)
            .ThenBy(static value => value.RuleId, StringComparer.Ordinal))
        {
            builder.AppendLine("  <article class=\"reference-summary-card\">");
            builder.AppendLine("    <div class=\"reference-summary-heading\">");
            builder.Append("      <strong>");
            builder.Append(EscapeHtmlText(analysis.Provider));
            builder.Append("</strong><span>");
            builder.Append(EscapeHtmlText(analysis.CredentialType));
            builder.Append("</span><code>");
            builder.Append(EscapeHtmlCode(analysis.RuleId));
            builder.AppendLine("</code>");
            builder.AppendLine("    </div>");
            builder.Append("    <p class=\"reference-summary-meta\"><span>Risk <code>");
            builder.Append(EscapeHtmlCode(analysis.Risk));
            builder.Append("</code></span><span>");
            builder.Append(analysis.RevocationAvailable ? "Revocation available" : "No revocation template");
            builder.Append("</span><span>");
            builder.Append(analysis.RecommendedActions.Count.ToString(CultureInfo.InvariantCulture));
            builder.Append(" actions</span><span>");
            builder.Append(analysis.RevocationGuidance.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine(" guidance items</span></p>");
            builder.Append("    <p class=\"reference-summary-detail\">Evidence keys: ");
            builder.Append(EscapeHtmlText(FormatEvidenceKeys(analysis)));
            builder.AppendLine("</p>");
            builder.AppendLine("  </article>");
        }

        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendReferenceCardFact(
        StringBuilder builder,
        string label,
        string value,
        bool code,
        bool wide)
    {
        builder.Append("      <div");
        if (wide)
        {
            builder.Append(" class=\"reference-card-wide\"");
        }

        builder.AppendLine(">");
        builder.Append("        <dt>");
        builder.Append(EscapeHtmlText(label));
        builder.AppendLine("</dt>");
        builder.Append("        <dd>");
        string displayValue = value.Length == 0 ? "-" : value;
        if (code && value.Length != 0)
        {
            builder.Append("<code>");
            builder.Append(EscapeHtmlCode(displayValue));
            builder.Append("</code>");
        }
        else
        {
            builder.Append(EscapeHtmlText(displayValue));
        }

        builder.AppendLine("</dd>");
        builder.AppendLine("      </div>");
    }

    private static void AppendAnalysisSchema(StringBuilder builder, List<CredentialAnalysis> analyses)
    {
        builder.AppendLine("## Analysis Report Shape");
        builder.AppendLine();
        builder.AppendLine("JSON reports use schema `picket.analysis.report.v1`. JSON Lines emits one `picket.analysis.v1` object per line with the same analysis fields.");
        builder.AppendLine();
        using JsonDocument document = JsonDocument.Parse(CredentialAnalysisReportWriter.WriteJson([analyses[0]]));
        JsonElement root = document.RootElement;
        AppendJsonShape(builder, "Analysis JSON report object", root);
        AppendJsonShape(builder, "Analysis JSON `analyses[]` object", root.GetProperty("analyses")[0]);
    }

    private static List<CredentialAnalysis> CreateSampleAnalyses()
    {
        List<Finding> findings = [.. s_analysisRuleIds.Select(static (ruleId, index) => CreateAnalysisFinding(
            ruleId,
            ruleId.Equals("picket-github-personal-access-token", StringComparison.Ordinal) ? "active" : "structurally-valid",
            string.Create(CultureInfo.InvariantCulture, $"src/generated/{index + 1}.txt"),
            index + 1))];
        Finding githubFinding = findings.First(static finding => finding.RuleID.Equals("picket-github-personal-access-token", StringComparison.Ordinal));
        var metadata = new Dictionary<string, CredentialAnalysisMetadata>(StringComparer.Ordinal)
        {
            [StableFindingFingerprint.Create(githubFinding)] = new CredentialAnalysisMetadata(
                "github:user/example",
                ["repo:read", "gist:read"],
                ["github:user"],
                ["provider=github", "endpoint=/user"]),
        };

        return CredentialAnalyzer.Analyze(findings, metadata);
    }

    private static Finding CreateAnalysisFinding(string ruleId, string validationState, string file, int line)
    {
        return new Finding(
            ruleId,
            string.Concat("Generated analysis fixture for ", ruleId),
            line,
            line,
            1,
            18,
            "secret=<redacted>",
            "<redacted>",
            file,
            string.Empty,
            "0123456789abcdef0123456789abcdef01234567",
            3.25,
            "Example Author",
            "author@example.invalid",
            "2026-07-07T00:00:00Z",
            "Generate validation analysis reference",
            ["generated", "documentation"],
            string.Create(CultureInfo.InvariantCulture, $"{file}:{ruleId}:{line}"),
            "secret=<redacted>",
            "https://example.invalid/picket/generated",
            validationState: validationState,
            blobSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }

    private static string FormatEvidenceKeys(CredentialAnalysis analysis)
    {
        string[] keys = [.. analysis.Evidence
            .Select(static value => ReadEvidenceKey(value))
            .Where(static value => value.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
        return FormatValueList(keys);
    }

    private static string ReadEvidenceKey(string value)
    {
        int separatorIndex = value.IndexOf('=');
        return separatorIndex <= 0 ? string.Empty : value[..separatorIndex];
    }
}
