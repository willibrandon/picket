using Picket.Engine;
using Picket.Report;
using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="PicketHtmlReportWriter" />.
/// </summary>
[TestClass]
public sealed class PicketHtmlReportWriterTests
{
    private const string BlobSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Verifies that an empty report is a complete static HTML document.
    /// </summary>
    [TestMethod]
    public void WriteReturnsCompleteEmptyReport()
    {
        string html = PicketHtmlReportWriter.Write([], []);

        Assert.Contains("<!doctype html>", html);
        Assert.Contains("<title>Picket Secret Scan Report</title>", html);
        Assert.Contains("Content-Security-Policy", html);
        Assert.Contains("<h1>Picket Secret Scan Report</h1>", html);
        Assert.Contains("<span>Findings</span><strong>0</strong>", html);
        Assert.Contains("<template id=\"picket-report-summary\" data-type=\"application/json\">", html);
        Assert.Contains("<p class=\"empty\">No findings.</p>", html);
        Assert.Contains("<p class=\"empty\">No rules were loaded.</p>", html);
        Assert.DoesNotContain("<script", html);
    }

    /// <summary>
    /// Verifies that findings and rules are written with HTML escaping.
    /// </summary>
    [TestMethod]
    public void WriteEscapesFindingsAndRules()
    {
        Finding finding = CreateFinding(
            ruleId: "rule<script>",
            description: "A <test> \"rule\"",
            file: "src/auth&config.txt",
            symlinkFile: string.Empty,
            match: "token=\"abc<123>\"",
            secret: "abc<123>",
            fingerprint: "finger&print",
            tags: ["sec<ret>"]);
        SecretRule rule = SecretRule.Create("rule<script>", "A <test> \"rule\"", "token=\"[^\"]+\"", tags: ["sec<ret>"]);

        string html = PicketHtmlReportWriter.Write([finding], [rule]);
        string fingerprint = StableFindingFingerprint.Create(finding);

        Assert.Contains("<span>Findings</span><strong>1</strong>", html);
        Assert.Contains("<span>Rules</span><strong>1</strong>", html);
        Assert.Contains("<span>Files</span><strong>1</strong>", html);
        Assert.Contains(".report-list{display:grid;gap:16px}", html);
        Assert.Contains(".finding-card,.rule-card{border:1px solid #d9ddd2;background:#fff;border-radius:8px", html);
        Assert.Contains(".field-grid{display:grid;gap:12px;align-items:stretch}", html);
        Assert.Contains(".finding-card .field-grid{grid-template-columns:minmax(220px,.85fr) minmax(420px,1.15fr)}", html);
        Assert.Contains(".field-wide{grid-column:1/-1}", html);
        Assert.Contains(".metadata{margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))", html);
        Assert.Contains(".metadata-item{display:block;border-left:2px solid #d9ddd2;padding-left:10px;min-width:0}", html);
        Assert.Contains(".metadata-item-long{grid-column:span 2}", html);
        Assert.Contains(".metadata dd code{white-space:normal;overflow-wrap:break-word;word-break:normal}", html);
        Assert.Contains("<div class=\"report-list findings-list\">", html);
        Assert.Contains("<div class=\"report-list rules-list\">", html);
        Assert.Contains("<article class=\"finding-card\">", html);
        Assert.Contains("<article class=\"rule-card\">", html);
        Assert.Contains("<span class=\"field-label\">Secret</span><code>abc&lt;123&gt;</code>", html);
        Assert.Contains("<span class=\"field-label\">Match</span><pre>token=&quot;abc&lt;123&gt;&quot;</pre>", html);
        Assert.Contains("<div class=\"field field-wide\"><span class=\"field-label\">Fingerprint</span>", html);
        Assert.Contains("<dl class=\"metadata\"><div class=\"metadata-item\"><dt>Severity</dt>", html);
        Assert.DoesNotContain("<table", html);
        Assert.Contains("rule&lt;script&gt;", html);
        Assert.Contains("A &lt;test&gt; &quot;rule&quot;", html);
        Assert.Contains("src/auth&amp;config.txt:1:2", html);
        Assert.Contains("token=&quot;abc&lt;123&gt;&quot;", html);
        Assert.Contains(fingerprint, html);
        Assert.DoesNotContain("finger&amp;print", html);
        Assert.Contains("Secret SHA-256", html);
        Assert.Contains("<div class=\"metadata-item metadata-item-long\"><dt>Secret SHA-256</dt>", html);
        Assert.Contains("6ed417714f0de0a4685ed766cb926df89182f22cd40646f59a9072f72f41c6e0", html);
        Assert.Contains("Blob SHA-256", html);
        Assert.Contains("<div class=\"metadata-item metadata-item-long\"><dt>Blob SHA-256</dt>", html);
        Assert.Contains(BlobSha256, html);
        Assert.Contains("<div class=\"metadata-item metadata-item-long\"><dt>Decode Path</dt><dd><code>base64</code></dd></div>", html);
        Assert.Contains("<dt>Validation</dt><dd><code>unknown</code></dd>", html);
        Assert.DoesNotContain("<dt>Docs</dt><dd><code></code></dd>", html);
        Assert.Contains("sec&lt;ret&gt;", html);
        Assert.DoesNotContain("<script>", html);
    }

    /// <summary>
    /// Verifies symlink display paths and safe fallback fingerprints.
    /// </summary>
    [TestMethod]
    public void WriteUsesSymlinkPathAndFallbackFingerprint()
    {
        Finding finding = CreateFinding(
            ruleId: "rule",
            description: string.Empty,
            file: "target.txt",
            symlinkFile: "link.txt",
            match: "match",
            secret: "secret",
            fingerprint: string.Empty,
            tags: []);

        string html = PicketHtmlReportWriter.Write([finding], []);
        string fingerprint = StableFindingFingerprint.Create(finding);

        Assert.Contains("link.txt:1:2", html);
        Assert.Contains(fingerprint, html);
        Assert.DoesNotContain("target.txt:1:2", html);
    }

    /// <summary>
    /// Verifies native HTML replaces lone surrogate code units with valid Unicode.
    /// </summary>
    [TestMethod]
    public void WriteReplacesLoneSurrogatesWithReplacementCharacter()
    {
        Finding finding = CreateFinding(
            ruleId: "rule",
            description: "desc\uD800",
            file: "target.txt",
            symlinkFile: string.Empty,
            match: "match\uD800",
            secret: "secret",
            fingerprint: string.Empty,
            tags: []);

        string html = PicketHtmlReportWriter.Write([finding], []);

        Assert.Contains("desc\uFFFD", html);
        Assert.Contains("match\uFFFD", html);
        Assert.DoesNotContain("\uD800", html);
    }

    private static Finding CreateFinding(
        string ruleId,
        string description,
        string file,
        string symlinkFile,
        string match,
        string secret,
        string fingerprint,
        IReadOnlyList<string> tags)
    {
        return new Finding(
            ruleId,
            description,
            1,
            1,
            2,
            10,
            match,
            secret,
            file,
            symlinkFile,
            string.Empty,
            2.5,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            tags,
            fingerprint,
            blobSha256: BlobSha256,
            decodePath: ["base64"]);
    }
}
