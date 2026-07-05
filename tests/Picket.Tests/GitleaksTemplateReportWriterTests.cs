using Picket.Engine;
using Picket.Report;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksTemplateReportWriter" />.
/// </summary>
[TestClass]
public sealed class GitleaksTemplateReportWriterTests
{
    /// <summary>
    /// Verifies the Gitleaks Markdown template fixture shape.
    /// </summary>
    [TestMethod]
    public void WriteRendersMarkdownRangeTemplate()
    {
        string report = GitleaksTemplateReportWriter.Write(
            [CreateFinding()],
            """
            | File | Line | Secret |
            |:-----|-----:|--------|
            {{ range . -}}
            | {{ .File }} | {{ .StartLine }} | {{ quote .Secret }} |
            {{ end -}}
            """);

        Assert.AreEqual("| File | Line | Secret |\n|:-----|-----:|--------|\n| auth.py | 1 | \"a secret\" |\n", report);
    }

    /// <summary>
    /// Verifies indexed ranges, variables, conditions, and tag iteration used by Gitleaks JSON templates.
    /// </summary>
    [TestMethod]
    public void WriteRendersIndexedJsonTemplate()
    {
        string report = GitleaksTemplateReportWriter.Write(
            [CreateFinding()],
            """
            [{{ $lastFinding := (sub (len . ) 1) }}
            {{- range $i, $finding := . }}{{with $finding}}
                {
                    "Line": {{ quote .Line }},
                    "Tags": [{{ $lastTag := (sub (len .Tags ) 1) }}{{ range $j, $tag := .Tags }}{{ quote . }}{{ if ne $j $lastTag }},{{ end }}{{ end }}],
                    "RuleID": {{ quote .RuleID }}
                }{{ if ne $i $lastFinding }},{{ end }}
            {{- end}}{{ end }}
            ]
            """);

        Assert.Contains("\"Line\": \"whole line containing secret\"", report);
        Assert.Contains("\"Tags\": [\"tag1\",\"tag2\",\"tag3\"]", report);
        Assert.Contains("\"RuleID\": \"test-rule\"", report);
    }

    /// <summary>
    /// Verifies that dangerous Sprig functions disabled by Gitleaks are rejected.
    /// </summary>
    [TestMethod]
    public void WriteRejectsDangerousFunctions()
    {
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(
            () => GitleaksTemplateReportWriter.Write([CreateFinding()], "{{ env \"SECRET\" }}"));

        Assert.Contains("function \"env\" not defined", exception.Message);
    }

    private static Finding CreateFinding()
    {
        return new Finding(
            "test-rule",
            "A test rule",
            1,
            2,
            1,
            2,
            "line containing secret",
            "a secret",
            "auth.py",
            string.Empty,
            "0000000000000000",
            0,
            "John Doe",
            "johndoe@example.com",
            "10-19-2003",
            "opps",
            ["tag1", "tag2", "tag3"],
            "fingerprint",
            "whole line containing secret");
    }
}
