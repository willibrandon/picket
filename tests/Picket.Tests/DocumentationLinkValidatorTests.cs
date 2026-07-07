using Picket.Docs;

namespace Picket.Tests;

/// <summary>
/// Tests the generated documentation local link validator.
/// </summary>
[TestClass]
public sealed class DocumentationLinkValidatorTests
{
    /// <summary>
    /// Verifies that same-page fragments, relative page links, and site-root links resolve.
    /// </summary>
    [TestMethod]
    public void ValidateDocumentationLinksAcceptsLocalPagesAndFragments()
    {
        using TempDirectory temp = TempDirectory.Create();
        string root = temp.Path;
        Directory.CreateDirectory(Path.Combine(root, "reference"));
        File.WriteAllText(
            Path.Combine(root, "index.md"),
            """
            # Home

            [Same page](#home)
            [Reference](reference/api.md#public-type)
            <a href="/picket/reference/api/#public-type">Reference route</a>
            [External](https://example.invalid/picket)
            """);
        File.WriteAllText(
            Path.Combine(root, "reference", "api.md"),
            """
            # API

            ## Public Type
            """);

        List<string> violations = DocumentationGenerator.ValidateDocumentationLinks(root);

        Assert.IsEmpty(violations);
    }

    /// <summary>
    /// Verifies that missing local pages and missing local fragments are reported.
    /// </summary>
    [TestMethod]
    public void ValidateDocumentationLinksReportsBrokenLocalTargets()
    {
        using TempDirectory temp = TempDirectory.Create();
        string root = temp.Path;
        Directory.CreateDirectory(Path.Combine(root, "reference"));
        File.WriteAllText(
            Path.Combine(root, "index.md"),
            """
            # Home

            [Missing page](reference/missing/)
            [Missing fragment](#missing)
            <a href="/picket/reference/api/#missing">Missing route fragment</a>
            """);
        File.WriteAllText(
            Path.Combine(root, "reference", "api.md"),
            """
            # API

            ## Public Type
            """);

        List<string> violations = DocumentationGenerator.ValidateDocumentationLinks(root);

        Assert.HasCount(3, violations);
        Assert.Contains("index.md:3: local link `reference/missing/` points to a missing page", violations);
        Assert.Contains("index.md:4: local link `#missing` points to missing fragment `#missing`", violations);
        Assert.Contains("index.md:5: local link `/picket/reference/api/#missing` points to missing fragment `#missing`", violations);
    }
}
