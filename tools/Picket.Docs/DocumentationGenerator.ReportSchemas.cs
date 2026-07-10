using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    private static void GenerateReportSchemaReference(string outputRoot)
    {
        SecretRule rule = CreateSampleReportRule();
        Finding finding = CreateSampleReportFinding();
        Finding[] findings = [finding];
        SecretRule[] rules = [rule];

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from deterministic sample output written by the Picket report writers. It documents field presence and ordering, not live finding values.");
        builder.AppendLine();
        AppendNativeReportSchemas(builder, findings, rules);
        AppendCompatibilityReportSchemas(builder, findings, rules);

        WriteMarkdown(
            Path.Combine(outputRoot, "report-schemas.md"),
            "Report Schema Reference",
            "Generated report schema reference for native and compatibility reports.",
            builder.ToString(),
            tableOfContents: false);
    }

    private static void AppendNativeReportSchemas(StringBuilder builder, Finding[] findings, SecretRule[] rules)
    {
        builder.AppendLine("## Native Reports");
        builder.AppendLine();
        builder.AppendLine("Native reports carry Picket schema metadata such as `picket.report.v1` and `picket.finding.v1`, stable hashes, validation state, provenance, and rule metadata.");
        builder.AppendLine();

        using (JsonDocument document = JsonDocument.Parse(PicketJsonReportWriter.Write(findings, rules)))
        {
            JsonElement root = document.RootElement;
            AppendJsonShape(builder, "Native JSON report object", root);
            AppendJsonShape(builder, "Native JSON `rules[]` object", root.GetProperty("rules")[0]);
            AppendJsonShape(builder, "Native JSON `findings[]` object", root.GetProperty("findings")[0]);
            AppendJsonShape(builder, "Native JSON `findings[].randomness` object", root.GetProperty("findings")[0].GetProperty("randomness"));
            AppendJsonShape(builder, "Native JSON `findings[].provenance` object", root.GetProperty("findings")[0].GetProperty("provenance"));
        }

        using (JsonDocument document = JsonDocument.Parse(PicketJsonlReportWriter.Write(findings, rules).Trim()))
        {
            AppendJsonShape(builder, "Native JSONL finding object", document.RootElement);
            AppendJsonShape(builder, "Native JSONL `randomness` object", document.RootElement.GetProperty("randomness"));
        }

        AppendCsvColumns(builder, "Native CSV columns", PicketCsvReportWriter.Write(findings, rules));
        AppendToonSections(builder, PicketToonReportWriter.Write(findings, rules));

        using (JsonDocument document = JsonDocument.Parse(PicketSarifReportWriter.Write(findings, rules)))
        {
            JsonElement root = document.RootElement;
            JsonElement run = root.GetProperty("runs")[0];
            JsonElement driver = run.GetProperty("tool").GetProperty("driver");
            AppendJsonShape(builder, "Native SARIF root object", root);
            AppendJsonShape(builder, "Native SARIF driver object", driver);
            AppendJsonShape(builder, "Native SARIF rule object", driver.GetProperty("rules")[0]);
            AppendJsonShape(builder, "Native SARIF result object", run.GetProperty("results")[0]);
            AppendJsonShape(builder, "Native SARIF result randomness object", run.GetProperty("results")[0].GetProperty("properties").GetProperty("randomness"));
        }

        using (JsonDocument document = JsonDocument.Parse(PicketGitLabCodeQualityReportWriter.Write(findings)))
        {
            AppendJsonShape(builder, "GitLab Code Quality object", document.RootElement[0]);
        }

        AppendXmlShape(builder, "Native JUnit XML elements", PicketJunitReportWriter.Write(findings, rules));
    }

    private static void AppendCompatibilityReportSchemas(StringBuilder builder, Finding[] findings, SecretRule[] rules)
    {
        builder.AppendLine("## Gitleaks-Compatible Reports");
        builder.AppendLine();
        builder.AppendLine("Compatibility reports keep the Gitleaks-shaped field names and ordering expected by existing integrations.");
        builder.AppendLine();

        using (JsonDocument document = JsonDocument.Parse(GitleaksJsonReportWriter.Write(findings)))
        {
            AppendJsonShape(builder, "Gitleaks-compatible JSON finding object", document.RootElement[0]);
        }

        AppendCsvColumns(builder, "Gitleaks-compatible CSV columns", GitleaksCsvReportWriter.Write(findings));
        AppendXmlShape(builder, "Gitleaks-compatible JUnit XML elements", GitleaksJunitReportWriter.Write(findings));

        using (JsonDocument document = JsonDocument.Parse(GitleaksSarifReportWriter.Write(findings, rules)))
        {
            JsonElement root = document.RootElement;
            JsonElement run = root.GetProperty("runs")[0];
            JsonElement driver = run.GetProperty("tool").GetProperty("driver");
            AppendJsonShape(builder, "Gitleaks-compatible SARIF root object", root);
            AppendJsonShape(builder, "Gitleaks-compatible SARIF driver object", driver);
            AppendJsonShape(builder, "Gitleaks-compatible SARIF result object", run.GetProperty("results")[0]);
        }
    }

    private static SecretRule CreateSampleReportRule()
    {
        return SecretRule.Create(
            "example-rule",
            "Example rule for generated report documentation.",
            "example-([A-Za-z0-9]+)",
            secretGroup: 1,
            keywords: ["example"],
            tags: ["sample", "documentation"],
            severity: "high",
            confidence: "medium",
            rulePack: "picket-default",
            provider: "Example",
            documentationUrl: "https://example.invalid/picket/rules/example-rule",
            randomnessThreshold: 0.8);
    }

    private static Finding CreateSampleReportFinding()
    {
        const string SampleSecret = "a8F2kL9mQ4xT7vN1zR6pW3cY";
        return new Finding(
            "example-rule",
            "Example rule for generated report documentation.",
            3,
            3,
            12,
            24,
            "value=example-a8F2kL9mQ4xT7vN1zR6pW3cY",
            SampleSecret,
            "src/example.txt",
            string.Empty,
            "0123456789abcdef0123456789abcdef01234567",
            3.25,
            "Example Author",
            "author@example.invalid",
            "2026-07-06T00:00:00Z",
            "Add generated report schema fixture",
            ["sample", "documentation"],
            "src/example.txt:example-rule:3",
            "value=example-a8F2kL9mQ4xT7vN1zR6pW3cY",
            "https://example.invalid/picket/blob/src/example.txt#L3",
            validationState: "structurally-valid",
            blobSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            decodePath: ["plain"],
            randomness: SecretRandomnessScorer.Assess(SampleSecret));
    }

    private static void AppendJsonShape(StringBuilder builder, string title, JsonElement value)
    {
        builder.Append("### ");
        builder.AppendLine(title);
        builder.AppendLine();
        builder.AppendLine("| Property | JSON type |");
        builder.AppendLine("|---|---|");
        foreach (JsonProperty property in value.EnumerateObject())
        {
            builder.Append("| `");
            builder.Append(EscapeTable(property.Name));
            builder.Append("` | `");
            builder.Append(EscapeTable(GetJsonType(property.Value)));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendCsvColumns(StringBuilder builder, string title, string csv)
    {
        string header = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0];
        string[] columns = header.Split(',');
        builder.Append("### ");
        builder.AppendLine(title);
        builder.AppendLine();
        builder.AppendLine("| Position | Column |");
        builder.AppendLine("|---:|---|");
        for (int i = 0; i < columns.Length; i++)
        {
            builder.Append("| ");
            builder.Append((i + 1).ToString(CultureInfo.InvariantCulture));
            builder.Append(" | `");
            builder.Append(EscapeTable(columns[i]));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendToonSections(StringBuilder builder, string toon)
    {
        builder.AppendLine("### Native TOON sections");
        builder.AppendLine();
        builder.AppendLine("| Section | Fields |");
        builder.AppendLine("|---|---|");
        foreach (string line in toon.Split('\n'))
        {
            if (!TryReadToonSection(line, out string section, out string fields))
            {
                continue;
            }

            builder.Append("| `");
            builder.Append(EscapeTable(section));
            builder.Append("` | `");
            builder.Append(EscapeTable(fields));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendXmlShape(StringBuilder builder, string title, string xml)
    {
        XDocument document = XDocument.Parse(xml);
        string[] elementNames = [.. document.Descendants()
            .Select(element => element.Name.LocalName)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
        builder.Append("### ");
        builder.AppendLine(title);
        builder.AppendLine();
        builder.AppendLine("| Element |");
        builder.AppendLine("|---|");
        foreach (string elementName in elementNames)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(elementName));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static bool TryReadToonSection(string line, out string section, out string fields)
    {
        section = string.Empty;
        fields = string.Empty;
        int countStart = line.IndexOf('[', StringComparison.Ordinal);
        int fieldsStart = line.IndexOf('{', StringComparison.Ordinal);
        int fieldsEnd = line.IndexOf('}', StringComparison.Ordinal);
        if (countStart <= 0 || fieldsStart <= countStart || fieldsEnd <= fieldsStart)
        {
            return false;
        }

        section = line[..countStart];
        fields = line[(fieldsStart + 1)..fieldsEnd];
        return true;
    }

    private static string GetJsonType(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.Object => "object",
            JsonValueKind.Array => GetJsonArrayType(value),
            JsonValueKind.String => "string",
            JsonValueKind.Number => "number",
            JsonValueKind.True or JsonValueKind.False => "boolean",
            JsonValueKind.Null => "null",
            _ => value.ValueKind.ToString(),
        };
    }

    private static string GetJsonArrayType(JsonElement value)
    {
        JsonElement.ArrayEnumerator elements = value.EnumerateArray();
        return elements.MoveNext()
            ? string.Concat("array<", GetJsonType(elements.Current), ">")
            : "array";
    }
}
