using System.Text;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    private void GenerateConfigSchemaReference(string outputRoot)
    {
        VerifyConfigLoaderCoverage();

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from the configuration schema supported by the current Picket config loaders.");
        builder.AppendLine();
        AppendConfigPrecedence(builder);
        AppendConfigSection(
            builder,
            "Top-Level Fields",
            "Top-level fields apply to the whole TOML document.",
            GetTopLevelConfigFields());
        AppendConfigSection(
            builder,
            "[extend]",
            "The `[extend]` table controls inheritance from another config or from the embedded default rule set.",
            GetExtendConfigFields());
        AppendConfigSection(
            builder,
            "[[rules]]",
            "Each `[[rules]]` table defines one scanner rule. Native metadata fields are ignored by older Gitleaks consumers but are used by Picket reports, rule QA, and native rule packs.",
            GetRuleConfigFields());
        AppendConfigSection(
            builder,
            "[[allowlists]] and [allowlist]",
            "Global allowlists suppress findings across rules. `[[allowlists]]` is the current plural form; `[allowlist]` is the deprecated Gitleaks-compatible singular form. The two forms cannot be mixed in the same config.",
            GetGlobalAllowlistConfigFields());
        AppendConfigSection(
            builder,
            "[[rules.allowlists]] and [rules.allowlist]",
            "Per-rule allowlists suppress findings only for the preceding `[[rules]]` entry. `[[rules.allowlists]]` is the current plural form; `[rules.allowlist]` is the deprecated Gitleaks-compatible singular form. The two forms cannot be mixed on the same rule.",
            GetRuleAllowlistConfigFields());
        AppendConfigSection(
            builder,
            "[[rules.required]]",
            "Required-rule entries make a rule conditional on another rule being present near the same evidence.",
            GetRequiredRuleConfigFields());
        AppendConfigValidationNotes(builder);

        WriteMarkdown(
            Path.Combine(outputRoot, "config-schema.md"),
            "Config Schema Reference",
            "Generated config schema reference for Picket-native and Gitleaks-compatible TOML.",
            builder.ToString(),
            tableOfContents: false);
    }

    private void VerifyConfigLoaderCoverage()
    {
        string gitleaksLoader = File.ReadAllText(Path.Combine(_repositoryRoot, "src", "Picket.Compat", "GitleaksConfigLoader.cs"));
        string picketLoader = File.ReadAllText(Path.Combine(_repositoryRoot, "src", "Picket.Compat", "PicketConfigLoader.cs"));

        foreach (string snippet in GetRequiredGitleaksConfigLoaderSnippets())
        {
            RequireConfigLoaderSnippet(gitleaksLoader, snippet, "GitleaksConfigLoader.cs");
        }

        foreach (string snippet in GetRequiredPicketConfigLoaderSnippets())
        {
            RequireConfigLoaderSnippet(picketLoader, snippet, "PicketConfigLoader.cs");
        }
    }

    private static void RequireConfigLoaderSnippet(string source, string snippet, string loaderName)
    {
        if (!source.Contains(snippet, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{loaderName} no longer contains expected config loader snippet: {snippet}");
        }
    }

    private static void AppendConfigPrecedence(StringBuilder builder)
    {
        builder.AppendLine("## Config Selection");
        builder.AppendLine();
        builder.AppendLine("Strict Gitleaks-compatible commands use this precedence:");
        builder.AppendLine();
        AppendOrderedConfigList(
            builder,
            [
                "`--config` / `-c`",
                "`GITLEAKS_CONFIG`",
                "`GITLEAKS_CONFIG_TOML`",
                "`{target}/.gitleaks.toml`",
                "embedded Gitleaks-compatible default config",
            ]);
        builder.AppendLine("Picket-native commands use this precedence:");
        builder.AppendLine();
        AppendOrderedConfigList(
            builder,
            [
                "`--config` / `-c`",
                "`PICKET_CONFIG`",
                "`PICKET_CONFIG_TOML`",
                "`GITLEAKS_CONFIG`",
                "`GITLEAKS_CONFIG_TOML`",
                "`{target}/.gitleaks.toml`",
                "embedded Picket default config",
            ]);
    }

    private static void AppendOrderedConfigList(StringBuilder builder, string[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            builder.Append(i + 1);
            builder.Append(". ");
            builder.AppendLine(values[i]);
        }

        builder.AppendLine();
    }

    private static void AppendConfigSection(
        StringBuilder builder,
        string title,
        string introduction,
        (string Name, string TomlType, string AppliesTo, string Notes)[] fields)
    {
        builder.Append("## ");
        builder.AppendLine(title);
        builder.AppendLine();
        builder.AppendLine(introduction);
        builder.AppendLine();
        builder.AppendLine("| Field | TOML type | Applies to | Notes |");
        builder.AppendLine("|---|---|---|---|");
        foreach ((string name, string tomlType, string appliesTo, string notes) in fields)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(name));
            builder.Append("` | `");
            builder.Append(EscapeTable(tomlType));
            builder.Append("` | ");
            builder.Append(EscapeTable(appliesTo));
            builder.Append(" | ");
            builder.Append(EscapeTable(notes));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
    }

    private static void AppendConfigValidationNotes(StringBuilder builder)
    {
        builder.AppendLine("## Validation Notes");
        builder.AppendLine();
        builder.AppendLine("- `id` is required for every rule.");
        builder.AppendLine("- A rule must provide `regex`, `path`, or both.");
        builder.AppendLine("- `secretGroup`, `entropy`, `withinLines`, and `withinColumns` must be non-negative.");
        builder.AppendLine("- `secretGroup` must reference an existing capture group when `regex` is present.");
        builder.AppendLine("- `extend.path` and `extend.useDefault` cannot both be set.");
        builder.AppendLine("- `extend.url` is parsed and ignored in strict compatibility mode because the pinned local Gitleaks behavior does not load URL extends.");
        builder.AppendLine("- Resolved configs are capped at 10,000 rules.");
        builder.AppendLine("- `targetRules` is valid only on global allowlists and every target rule ID must exist after extend resolution.");
        builder.AppendLine("- Each allowlist must include at least one of `commits`, `paths`, `regexes`, or `stopwords`.");
        builder.AppendLine("- Every `[[rules.required]]` ID must refer to another configured rule.");
        builder.AppendLine("- Picket-native `picket-*` rules require both `examples` and `negativeExamples` during `picket rules check`.");
        builder.AppendLine();
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetTopLevelConfigFields()
    {
        return
        [
            ("minVersion", "string", "strict + native", "Accepted Gitleaks-compatible version gate. A leading `v` is allowed."),
        ];
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetExtendConfigFields()
    {
        return
        [
            ("path", "string", "strict + native", "Loads another local TOML config as the base config."),
            ("url", "string", "strict + native", "Accepted for compatibility and ignored by the current loader."),
            ("useDefault", "bool", "strict + native", "Extends the embedded Gitleaks-compatible default rule set."),
            ("disabledRules", "string[]", "strict + native", "Removes inherited rules by ID before merging local rules."),
        ];
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetRuleConfigFields()
    {
        return
        [
            ("id", "string", "strict + native", "Stable rule identifier. Required."),
            ("description", "string", "strict + native", "Human-readable rule description."),
            ("regex", "string", "strict + native", "Rule regex pattern."),
            ("path", "string", "strict + native", "Path regex pattern."),
            ("secretGroup", "integer", "strict + native", "Capture group containing the secret. `0` keeps Gitleaks-compatible automatic behavior."),
            ("entropy", "number", "strict + native", "Minimum Shannon entropy threshold. The comparison is strict `>`."),
            ("randomnessThreshold", "number", "native", "Minimum deterministic randomness score from `0.0` through `1.0`. Zero disables score filtering."),
            ("keywords", "string[]", "strict + native", "Literal prefilter terms for the rule."),
            ("tags", "string[]", "strict + native", "Rule tags copied into findings and reports."),
            ("skipReport", "bool", "strict + native", "Runs the rule but omits matching findings from reports."),
            ("severity", "string", "native metadata", "Native severity label used in Picket reports and triage."),
            ("confidence", "string", "native metadata", "Native confidence label used in Picket reports and triage."),
            ("rulePack", "string", "native metadata", "Native rule pack name."),
            ("provider", "string", "native metadata", "Provider or ecosystem that owns the rule."),
            ("documentationUrl", "string", "native metadata", "Rule documentation URL."),
            ("validation", "string[]", "native metadata", "Stable validation template identifiers supported by the rule."),
            ("revocation", "string[]", "native metadata", "Stable revocation template identifiers supported by the rule."),
            ("deprecated", "bool", "native metadata", "Marks a rule as deprecated while keeping it parseable for compatibility and migration workflows."),
            ("examples", "string[]", "native rule QA", "Positive examples that must produce findings during `picket rules check`."),
            ("negativeExamples", "string[]", "native rule QA", "Negative examples that must not produce findings during `picket rules check`."),
        ];
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetGlobalAllowlistConfigFields()
    {
        return
        [
            ("description", "string", "strict + native", "Human-readable allowlist description."),
            ("condition", "string", "strict + native", "`OR`, `||`, `AND`, or `&&`. Empty means `OR`."),
            ("commits", "string[]", "strict + native", "Commit SHA values to suppress."),
            ("paths", "string[]", "strict + native", "Path regex patterns to suppress."),
            ("regexTarget", "string", "strict + native", "`secret`, `match`, or `line`. Empty means `secret`."),
            ("regexes", "string[]", "strict + native", "Regex patterns matched against the selected `regexTarget`."),
            ("stopwords", "string[]", "strict + native", "Case-insensitive stopwords matched against the secret."),
            ("targetRules", "string[]", "strict + native", "Restricts a global allowlist to the listed rule IDs."),
        ];
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetRuleAllowlistConfigFields()
    {
        return
        [
            ("description", "string", "strict + native", "Human-readable allowlist description."),
            ("condition", "string", "strict + native", "`OR`, `||`, `AND`, or `&&`. Empty means `OR`."),
            ("commits", "string[]", "strict + native", "Commit SHA values to suppress."),
            ("paths", "string[]", "strict + native", "Path regex patterns to suppress."),
            ("regexTarget", "string", "strict + native", "`secret`, `match`, or `line`. Empty means `secret`."),
            ("regexes", "string[]", "strict + native", "Regex patterns matched against the selected `regexTarget`."),
            ("stopwords", "string[]", "strict + native", "Case-insensitive stopwords matched against the secret."),
        ];
    }

    private static (string Name, string TomlType, string AppliesTo, string Notes)[] GetRequiredRuleConfigFields()
    {
        return
        [
            ("id", "string", "native", "Supporting rule ID required by the current rule."),
            ("withinLines", "integer", "native", "Maximum line distance from the primary finding."),
            ("withinColumns", "integer", "native", "Maximum column distance from the primary finding."),
        ];
    }

    private static string[] GetRequiredGitleaksConfigLoaderSnippets()
    {
        return
        [
            "GITLEAKS_CONFIG",
            "GITLEAKS_CONFIG_TOML",
            ".gitleaks.toml",
            "key.Equals(\"minVersion\", StringComparison.Ordinal)",
            "table.Equals(\"extend\", StringComparison.Ordinal)",
            "table.Equals(\"rules\", StringComparison.Ordinal)",
            "table.Equals(\"allowlists\", StringComparison.Ordinal)",
            "table.Equals(\"allowlist\", StringComparison.Ordinal)",
            "table.Equals(\"rules.allowlists\", StringComparison.Ordinal)",
            "table.Equals(\"rules.allowlist\", StringComparison.Ordinal)",
            "table.Equals(\"rules.required\", StringComparison.Ordinal)",
            "case \"path\":",
            "case \"url\":",
            "case \"useDefault\":",
            "case \"disabledRules\":",
            "case \"description\":",
            "case \"condition\":",
            "case \"commits\":",
            "case \"paths\":",
            "case \"regexTarget\":",
            "case \"regexes\":",
            "case \"stopwords\":",
            "case \"targetRules\":",
            "case \"id\":",
            "case \"withinLines\":",
            "case \"withinColumns\":",
            "case \"regex\":",
            "case \"secretGroup\":",
            "case \"entropy\":",
            "case \"randomnessThreshold\":",
            "case \"keywords\":",
            "case \"tags\":",
            "case \"skipReport\":",
            "case \"severity\":",
            "case \"confidence\":",
            "case \"rulePack\":",
            "case \"provider\":",
            "case \"documentationUrl\":",
            "case \"examples\":",
            "case \"negativeExamples\":",
        ];
    }

    private static string[] GetRequiredPicketConfigLoaderSnippets()
    {
        return
        [
            "PICKET_CONFIG",
            "PICKET_CONFIG_TOML",
            "GITLEAKS_CONFIG",
            "GITLEAKS_CONFIG_TOML",
            ".gitleaks.toml",
            "EmbeddedPicketConfig.Toml",
        ];
    }
}
