using Picket.Engine;
using Picket.Rules;
using System.Globalization;
using System.Text;

namespace Picket.Report;

/// <summary>
/// Writes self-contained Picket-native HTML reports.
/// </summary>
public static class PicketHtmlReportWriter
{
    /// <summary>
    /// Writes findings and rule metadata to a static HTML report.
    /// </summary>
    /// <param name="findings">The findings to write.</param>
    /// <param name="rules">The rules used for the scan.</param>
    /// <returns>A complete HTML document with a trailing newline.</returns>
    public static string Write(IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        builder.Append("<!doctype html>\n");
        builder.Append("<html lang=\"en\">\n");
        WriteHead(builder);
        builder.Append("<body>\n");
        builder.Append("<main>\n");
        builder.Append("<header>\n");
        builder.Append("<p class=\"eyebrow\">picket</p>\n");
        builder.Append("<h1>Picket Secret Scan Report</h1>\n");
        builder.Append("</header>\n");
        WriteSummary(builder, findings, rules);
        WriteEmbeddedSummary(builder, findings);
        WriteFindings(builder, findings, PicketFindingMetadata.CreateRuleIndex(rules));
        WriteRules(builder, rules);
        builder.Append("</main>\n");
        builder.Append("</body>\n");
        builder.Append("</html>\n");
        return builder.ToString();
    }

    private static void WriteHead(StringBuilder builder)
    {
        builder.Append("<head>\n");
        builder.Append("<meta charset=\"utf-8\">\n");
        builder.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        builder.Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">\n");
        builder.Append("<title>Picket Secret Scan Report</title>\n");
        builder.Append("<style>");
        builder.Append(":root{color-scheme:light dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:#f7f7f4;color:#161814}");
        builder.Append("body{margin:0;background:#f7f7f4;color:#161814}");
        builder.Append("main{max-width:1440px;margin:0 auto;padding:32px 24px 48px}");
        builder.Append("header{margin-bottom:24px}");
        builder.Append(".eyebrow{margin:0 0 4px;color:#596052;font-size:13px;text-transform:uppercase}");
        builder.Append("h1{margin:0;font-size:32px;line-height:1.15;font-weight:700}");
        builder.Append("h2{margin:32px 0 12px;font-size:20px;line-height:1.25}");
        builder.Append(".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0 28px}");
        builder.Append(".metric{border:1px solid #d9ddd2;background:#fff;border-radius:6px;padding:14px 16px}");
        builder.Append(".metric span{display:block;color:#596052;font-size:13px}");
        builder.Append(".metric strong{display:block;margin-top:2px;font-size:24px}");
        builder.Append(".report-list{display:grid;gap:16px}");
        builder.Append(".finding-card,.rule-card{border:1px solid #d9ddd2;background:#fff;border-radius:8px;padding:18px 20px;min-width:0}");
        builder.Append(".finding-card{display:grid;gap:14px}.rule-card{display:grid;gap:12px}");
        builder.Append(".card-header{display:grid;grid-template-columns:minmax(0,1fr) minmax(240px,420px);gap:16px;align-items:start}");
        builder.Append(".card-title{display:grid;gap:6px;min-width:0}.card-title h3{margin:0;font-size:16px;line-height:1.35}.card-title code{overflow-wrap:anywhere;word-break:break-word}");
        builder.Append(".card-description{margin:0;color:#30352c;line-height:1.5;max-width:88ch}");
        builder.Append(".card-location{margin:0;display:grid;gap:4px;min-width:0}");
        builder.Append(".field-grid{display:grid;gap:12px;align-items:stretch}");
        builder.Append(".finding-card .field-grid{grid-template-columns:minmax(220px,.85fr) minmax(420px,1.15fr)}");
        builder.Append(".rule-card .field-grid{grid-template-columns:minmax(320px,1.4fr) minmax(220px,.9fr) minmax(180px,.7fr)}");
        builder.Append(".field{border:1px solid #e0e4d8;background:#fbfcf8;border-radius:6px;padding:12px;min-width:0}");
        builder.Append(".field-wide{grid-column:1/-1}");
        builder.Append(".field-label{display:block;margin-bottom:6px;color:#596052;font-size:11px;font-weight:650;line-height:1.2;text-transform:uppercase}");
        builder.Append(".field code,.field pre,.card-location code{display:block;min-width:0;overflow-wrap:anywhere;word-break:break-word}");
        builder.Append("code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,\"Liberation Mono\",monospace}");
        builder.Append("code{font-size:13px}");
        builder.Append("pre{margin:0;white-space:pre-wrap;word-break:break-word;font-size:13px;line-height:1.45}");
        builder.Append(".empty{border:1px solid #d9ddd2;background:#fff;border-radius:6px;padding:20px;color:#596052}");
        builder.Append(".tags{display:flex;flex-wrap:wrap;gap:6px}");
        builder.Append(".tag{border:1px solid #cfd5c6;background:#f4f6ef;border-radius:999px;padding:2px 8px;font-size:12px;color:#30352c}");
        builder.Append(".metadata{margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px 16px;font-size:13px;line-height:1.35}");
        builder.Append(".metadata-item{display:block;border-left:2px solid #d9ddd2;padding-left:10px;min-width:0}");
        builder.Append(".metadata-item-long{grid-column:span 2}");
        builder.Append(".metadata dt{margin:0 0 3px;color:#596052;font-size:11px;font-weight:650;line-height:1.2;text-transform:uppercase;white-space:normal}.metadata dd{margin:0;min-width:0}.metadata dd code{white-space:normal;overflow-wrap:break-word;word-break:normal}");
        builder.Append("@media (max-width:900px){main{padding:24px 16px 40px}.card-header,.field-grid,.finding-card .field-grid,.rule-card .field-grid{grid-template-columns:1fr}.field-wide,.metadata-item-long{grid-column:auto}}");
        builder.Append("@media (prefers-color-scheme:dark){:root,body{background:#151713;color:#f1f4eb}.metric,.finding-card,.rule-card,.field,.empty{background:#1d211a;border-color:#3a4233}.field{background:#181c15}.card-description,.field-label,.eyebrow,.metric span,.empty,.metadata dt{color:#b5bcae}.metadata-item{border-color:#3a4233}.tag{background:#293023;border-color:#4b5542;color:#f1f4eb}}");
        builder.Append("</style>\n");
        builder.Append("</head>\n");
    }

    private static void WriteSummary(StringBuilder builder, IReadOnlyList<Finding> findings, IReadOnlyList<SecretRule> rules)
    {
        builder.Append("<section aria-labelledby=\"summary-heading\">\n");
        builder.Append("<h2 id=\"summary-heading\">Summary</h2>\n");
        builder.Append("<div class=\"summary\">\n");
        WriteMetric(builder, "Findings", findings.Count);
        WriteMetric(builder, "Rules", rules.Count);
        WriteMetric(builder, "Files", CountDistinctFindingFiles(findings));
        builder.Append("</div>\n");
        builder.Append("</section>\n");
    }

    private static void WriteEmbeddedSummary(StringBuilder builder, IReadOnlyList<Finding> findings)
    {
        builder.Append("<template id=\"picket-report-summary\" data-type=\"application/json\">");
        builder.Append('{');
        WriteJsonString(builder, "schema", "picket.html-summary.v1", comma: true);
        WriteJsonString(builder, "format", "picket-html", comma: true);
        builder.Append("\"findings\":[");
        for (int i = 0; i < findings.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            WriteEmbeddedFindingSummary(builder, findings[i]);
        }

        builder.Append("]}");
        builder.Append("</template>\n");
    }

    private static void WriteEmbeddedFindingSummary(StringBuilder builder, Finding finding)
    {
        builder.Append('{');
        WriteJsonString(builder, "ruleId", finding.RuleID, comma: true);
        WriteJsonString(builder, "path", CreateLocationPath(finding), comma: true);
        WriteJsonNumber(builder, "line", finding.StartLine, comma: true);
        WriteJsonNumber(builder, "startColumn", finding.StartColumn, comma: true);
        WriteJsonString(builder, "fingerprint", CreateFingerprint(finding), comma: finding.Randomness is not null);
        if (finding.Randomness is not null)
        {
            WriteJsonRandomnessNumber(builder, "randomnessScore", finding.Randomness.Score, comma: true);
            WriteJsonString(builder, "randomnessClassification", finding.Randomness.Classification, comma: true);
            WriteJsonString(builder, "randomnessModel", finding.Randomness.Model, comma: false);
        }

        builder.Append('}');
    }

    private static void WriteJsonRandomnessNumber(StringBuilder builder, string name, double value, bool comma)
    {
        builder.Append('"');
        builder.Append(name);
        builder.Append("\":");
        builder.Append(PicketFindingMetadata.FormatRandomnessNumber(value));
        if (comma)
        {
            builder.Append(',');
        }
    }

    private static void WriteMetric(StringBuilder builder, string label, int value)
    {
        builder.Append("<div class=\"metric\"><span>");
        AppendHtml(builder, label);
        builder.Append("</span><strong>");
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        builder.Append("</strong></div>\n");
    }

    private static int CountDistinctFindingFiles(IReadOnlyList<Finding> findings)
    {
        var files = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < findings.Count; i++)
        {
            files.Add(CreateLocationPath(findings[i]));
        }

        return files.Count;
    }

    private static void WriteFindings(StringBuilder builder, IReadOnlyList<Finding> findings, IReadOnlyDictionary<string, SecretRule> ruleIndex)
    {
        builder.Append("<section aria-labelledby=\"findings-heading\">\n");
        builder.Append("<h2 id=\"findings-heading\">Findings</h2>\n");
        if (findings.Count == 0)
        {
            builder.Append("<p class=\"empty\">No findings.</p>\n");
            builder.Append("</section>\n");
            return;
        }

        builder.Append("<div class=\"report-list findings-list\">\n");
        for (int i = 0; i < findings.Count; i++)
        {
            WriteFinding(builder, findings[i], PicketFindingMetadata.FindRule(ruleIndex, findings[i]));
        }

        builder.Append("</div>\n");
        builder.Append("</section>\n");
    }

    private static void WriteFinding(StringBuilder builder, Finding finding, SecretRule? rule)
    {
        builder.Append("<article class=\"finding-card\">\n");
        builder.Append("<div class=\"card-header\"><div class=\"card-title\"><h3><code>");
        AppendHtml(builder, finding.RuleID);
        builder.Append("</code></h3>");
        if (finding.Description.Length > 0)
        {
            builder.Append("<p class=\"card-description\">");
            AppendHtml(builder, finding.Description);
            builder.Append("</p>");
        }

        builder.Append("</div><p class=\"card-location\"><span class=\"field-label\">Location</span><code>");
        AppendHtml(builder, CreateLocationPath(finding));
        builder.Append(':');
        builder.Append(finding.StartLine.ToString(CultureInfo.InvariantCulture));
        builder.Append(':');
        builder.Append(finding.StartColumn.ToString(CultureInfo.InvariantCulture));
        builder.Append("</code></p></div>\n");
        builder.Append("<div class=\"field-grid\">");
        WriteField(builder, "Secret", finding.Secret, multiline: false);
        WriteField(builder, "Match", finding.Match, multiline: true);
        WriteField(builder, "Fingerprint", CreateFingerprint(finding), multiline: false, fieldClass: "field field-wide");
        builder.Append("</div>\n");
        WriteFindingMetadata(builder, finding, rule);
        builder.Append("<div>");
        builder.Append("<span class=\"field-label\">Tags</span>");
        WriteTags(builder, finding.Tags);
        builder.Append("</div>\n");
        builder.Append("</article>\n");
    }

    private static void WriteFindingMetadata(StringBuilder builder, Finding finding, SecretRule? rule)
    {
        builder.Append("<dl class=\"metadata\">");
        WriteMetadata(builder, "Severity", PicketFindingMetadata.CreateSeverity(rule));
        WriteMetadata(builder, "Confidence", PicketFindingMetadata.CreateConfidence(rule));
        WriteOptionalMetadata(builder, "Rule Pack", PicketFindingMetadata.CreateRulePack(rule));
        WriteOptionalMetadata(builder, "Provider", PicketFindingMetadata.CreateProvider(rule));
        WriteOptionalMetadata(builder, "Docs", PicketFindingMetadata.CreateDocumentationUrl(rule));
        WriteMetadata(builder, "Validation", PicketFindingMetadata.CreateValidationState(finding));
        if (finding.Randomness is not null)
        {
            WriteMetadata(builder, "Randomness", string.Concat(
                PicketFindingMetadata.FormatRandomnessNumber(finding.Randomness.Score),
                " (",
                finding.Randomness.Classification,
                ")"));
            WriteMetadata(builder, "Randomness Model", finding.Randomness.Model);
            WriteOptionalMetadata(builder, "Randomness Signals", string.Join(", ", finding.Randomness.Signals));
        }

        WriteMetadata(builder, "Provenance", PicketFindingMetadata.CreateProvenanceType(finding));
        WriteOptionalMetadata(builder, "Secret SHA-256", PicketFindingMetadata.CreateSecretSha256(finding));
        WriteOptionalMetadata(builder, "Blob SHA-256", PicketFindingMetadata.CreateBlobSha256(finding));
        WriteOptionalMetadata(builder, "Decode Path", string.Join(" > ", PicketFindingMetadata.CreateDecodePath(finding)));
        builder.Append("</dl>");
    }

    private static void WriteOptionalMetadata(StringBuilder builder, string name, string value)
    {
        if (value.Length != 0)
        {
            WriteMetadata(builder, name, value);
        }
    }

    private static void WriteMetadata(StringBuilder builder, string name, string value)
    {
        builder.Append("<div class=\"");
        builder.Append(CreateMetadataClass(name));
        builder.Append("\"><dt>");
        AppendHtml(builder, name);
        builder.Append("</dt><dd><code>");
        AppendHtml(builder, value);
        builder.Append("</code></dd></div>");
    }

    private static string CreateMetadataClass(string name)
    {
        return name is "Docs" or "Secret SHA-256" or "Blob SHA-256" or "Decode Path"
            ? "metadata-item metadata-item-long"
            : "metadata-item";
    }

    private static void WriteRules(StringBuilder builder, IReadOnlyList<SecretRule> rules)
    {
        builder.Append("<section aria-labelledby=\"rules-heading\">\n");
        builder.Append("<h2 id=\"rules-heading\">Rules</h2>\n");
        if (rules.Count == 0)
        {
            builder.Append("<p class=\"empty\">No rules were loaded.</p>\n");
            builder.Append("</section>\n");
            return;
        }

        builder.Append("<div class=\"report-list rules-list\">\n");
        for (int i = 0; i < rules.Count; i++)
        {
            WriteRule(builder, rules[i]);
        }

        builder.Append("</div>\n");
        builder.Append("</section>\n");
    }

    private static void WriteRule(StringBuilder builder, SecretRule rule)
    {
        builder.Append("<article class=\"rule-card\">\n");
        builder.Append("<div class=\"card-title\"><h3><code>");
        AppendHtml(builder, rule.Id);
        builder.Append("</code></h3>");
        if (rule.Description.Length > 0)
        {
            builder.Append("<p class=\"card-description\">");
            AppendHtml(builder, rule.Description);
            builder.Append("</p>");
        }

        builder.Append("</div>\n");
        builder.Append("<div class=\"field-grid\">");
        WriteField(builder, "Pattern", rule.Pattern, multiline: true);
        builder.Append("<div class=\"field\">");
        builder.Append("<span class=\"field-label\">Metadata</span>");
        WriteRuleMetadata(builder, rule);
        builder.Append("</div>");
        builder.Append("<div class=\"field\">");
        builder.Append("<span class=\"field-label\">Tags</span>");
        WriteTags(builder, rule.Tags);
        builder.Append("</div>");
        builder.Append("</div>\n");
        builder.Append("</article>\n");
    }

    private static void WriteField(StringBuilder builder, string label, string value, bool multiline, string fieldClass = "field")
    {
        builder.Append("<div class=\"");
        builder.Append(fieldClass);
        builder.Append("\"><span class=\"field-label\">");
        AppendHtml(builder, label);
        builder.Append("</span>");
        if (multiline)
        {
            builder.Append("<pre>");
            AppendHtml(builder, value);
            builder.Append("</pre>");
        }
        else
        {
            builder.Append("<code>");
            AppendHtml(builder, value);
            builder.Append("</code>");
        }

        builder.Append("</div>");
    }

    private static void WriteRuleMetadata(StringBuilder builder, SecretRule rule)
    {
        builder.Append("<dl class=\"metadata\">");
        WriteMetadata(builder, "Severity", PicketFindingMetadata.CreateSeverity(rule));
        WriteMetadata(builder, "Confidence", PicketFindingMetadata.CreateConfidence(rule));
        WriteOptionalMetadata(builder, "Rule Pack", PicketFindingMetadata.CreateRulePack(rule));
        WriteOptionalMetadata(builder, "Provider", PicketFindingMetadata.CreateProvider(rule));
        WriteOptionalMetadata(builder, "Docs", PicketFindingMetadata.CreateDocumentationUrl(rule));
        builder.Append("</dl>");
    }

    private static void WriteTags(StringBuilder builder, IReadOnlyList<string> tags)
    {
        if (tags.Count == 0)
        {
            builder.Append("<span class=\"empty-inline\">none</span>");
            return;
        }

        builder.Append("<span class=\"tags\">");
        for (int i = 0; i < tags.Count; i++)
        {
            builder.Append("<span class=\"tag\">");
            AppendHtml(builder, tags[i]);
            builder.Append("</span>");
        }

        builder.Append("</span>");
    }

    private static void WriteJsonString(StringBuilder builder, string name, string value, bool comma)
    {
        AppendJsonString(builder, name);
        builder.Append(':');
        AppendJsonString(builder, value);
        WriteJsonComma(builder, comma);
    }

    private static void WriteJsonNumber(StringBuilder builder, string name, int value, bool comma)
    {
        AppendJsonString(builder, name);
        builder.Append(':');
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        WriteJsonComma(builder, comma);
    }

    private static void WriteJsonComma(StringBuilder builder, bool comma)
    {
        if (comma)
        {
            builder.Append(',');
        }
    }

    private static void AppendJsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case '<':
                    builder.Append("\\u003c");
                    break;
                case '>':
                    builder.Append("\\u003e");
                    break;
                case '&':
                    builder.Append("\\u0026");
                    break;
                case 0x2028:
                    builder.Append("\\u2028");
                    break;
                case 0x2029:
                    builder.Append("\\u2029");
                    break;
                default:
                    if (rune.Value < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(rune.Value.ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(rune.ToString());
                    }

                    break;
            }
        }

        builder.Append('"');
    }

    private static string CreateFingerprint(Finding finding)
    {
        return PicketFindingMetadata.CreateFingerprint(finding);
    }

    private static string CreateLocationPath(Finding finding)
    {
        return finding.SymlinkFile.Length == 0 ? finding.File : finding.SymlinkFile;
    }

    private static void AppendHtml(StringBuilder builder, string value)
    {
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '&':
                    builder.Append("&amp;");
                    break;
                case '<':
                    builder.Append("&lt;");
                    break;
                case '>':
                    builder.Append("&gt;");
                    break;
                case '"':
                    builder.Append("&quot;");
                    break;
                case '\'':
                    builder.Append("&#39;");
                    break;
                default:
                    builder.Append(rune.ToString());
                    break;
            }
        }
    }
}
