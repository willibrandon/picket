using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Go regular-expression compatibility at the Scout compilation boundary.
/// </summary>
[TestClass]
public sealed class GitleaksRegexDialectTests
{
    /// <summary>
    /// Verifies Go Perl classes do not adopt Unicode membership outside character classes.
    /// </summary>
    [TestMethod]
    [DataRow(@"\d+", "\u0661")]
    [DataRow(@"\s+", "\u00A0")]
    [DataRow(@"\w+", "\u00E9")]
    public void ScanUsesAsciiPositivePerlClasses(string pattern, string input)
    {
        IReadOnlyList<Finding> findings = Scan(pattern, input);

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies complementary Go Perl classes match non-ASCII members as whole UTF-8 scalars.
    /// </summary>
    [TestMethod]
    [DataRow(@"\D+", "\u0661")]
    [DataRow(@"\S+", "\u00A0")]
    [DataRow(@"\W+", "\u00E9")]
    public void ScanUsesAsciiComplementaryPerlClasses(string pattern, string input)
    {
        IReadOnlyList<Finding> findings = Scan(pattern, input);

        Assert.HasCount(1, findings);
        Assert.AreEqual(input, findings[0].Secret);
    }

    /// <summary>
    /// Verifies Go Perl classes retain their ASCII definitions inside character classes.
    /// </summary>
    [TestMethod]
    [DataRow(@"[\d]+", "\u0661", false)]
    [DataRow(@"[\s]+", "\u00A0", false)]
    [DataRow(@"[\w]+", "\u00E9", false)]
    [DataRow(@"[\D]+", "\u0661", true)]
    [DataRow(@"[\S]+", "\u00A0", true)]
    [DataRow(@"[\W]+", "\u00E9", true)]
    [DataRow(@"[^\D]+", "5", true)]
    [DataRow(@"[^\D]+", "\u0661", false)]
    [DataRow(@"[^\S]+", " ", true)]
    [DataRow(@"[^\S]+", "\u00A0", false)]
    [DataRow(@"[^\W]+", "A", true)]
    [DataRow(@"[^\W]+", "\u00E9", false)]
    public void ScanTranslatesPerlClassesWithinCharacterClasses(string pattern, string input, bool expectedMatch)
    {
        IReadOnlyList<Finding> findings = Scan(pattern, input);

        if (expectedMatch)
        {
            Assert.HasCount(1, findings);
            Assert.AreEqual(input, findings[0].Secret);
        }
        else
        {
            Assert.IsEmpty(findings);
        }
    }

    /// <summary>
    /// Verifies Go word boundaries use ASCII word membership around non-ASCII text.
    /// </summary>
    [TestMethod]
    public void ScanUsesAsciiWordBoundaries()
    {
        string nonAsciiWord = "\u00E9";
        Assert.IsEmpty(Scan(string.Concat(@"\b", nonAsciiWord, @"\b"), nonAsciiWord));

        IReadOnlyList<Finding> asciiFindings = Scan(@"\bA\b", "A");
        IReadOnlyList<Finding> nonBoundaryFindings = Scan(string.Concat(@"\B", nonAsciiWord, @"\B"), nonAsciiWord);

        Assert.HasCount(1, asciiFindings);
        Assert.HasCount(1, nonBoundaryFindings);
    }

    /// <summary>
    /// Verifies explicit Unicode properties remain enabled by the dialect translation.
    /// </summary>
    [TestMethod]
    public void ScanPreservesExplicitUnicodeProperties()
    {
        IReadOnlyList<Finding> findings = Scan(@"\p{Greek}+", "\u03B4\u03B5\u03B9");

        Assert.HasCount(1, findings);
        Assert.AreEqual("\u03B4\u03B5\u03B9", findings[0].Secret);
        Assert.AreEqual(1.2924813032150269, findings[0].Entropy);
    }

    /// <summary>
    /// Verifies case-insensitive matching retains Unicode simple case folding.
    /// </summary>
    [TestMethod]
    public void ScanPreservesUnicodeCaseFolding()
    {
        IReadOnlyList<Finding> findings = Scan(string.Concat("(?i)", "\u03B4", "+"), "\u0394");

        Assert.HasCount(1, findings);
        Assert.AreEqual("\u0394", findings[0].Secret);
        Assert.AreEqual(0.5, findings[0].Entropy);
    }

    /// <summary>
    /// Verifies Unicode entropy thresholds reproduce Gitleaks' rune-count and byte-length calculation.
    /// </summary>
    [TestMethod]
    public void ScanUsesGitleaksUnicodeEntropyForThresholds()
    {
        const string secret = "\u00E9";
        SecretRule rule = SecretRule.Create("dialect", "Dialect test", secret, entropy: 0.75);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            Encoding.UTF8.GetBytes(secret),
            "input.txt",
            rules,
            maxDecodeDepth: 0));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies an escaped backslash before a shorthand letter remains literal.
    /// </summary>
    [TestMethod]
    public void ScanPreservesEscapedShorthandText()
    {
        IReadOnlyList<Finding> findings = Scan(@"\\w", @"\w");

        Assert.HasCount(1, findings);
        Assert.AreEqual(@"\w", findings[0].Secret);
    }

    /// <summary>
    /// Verifies POSIX character classes are not mistaken for nested bracket expressions.
    /// </summary>
    [TestMethod]
    public void ScanPreservesPosixCharacterClasses()
    {
        IReadOnlyList<Finding> findings = Scan("[[:alpha:]]+", "token");

        Assert.HasCount(1, findings);
        Assert.AreEqual("token", findings[0].Secret);
    }

    /// <summary>
    /// Verifies complementary ASCII classes consume malformed UTF-8 bytes like Go regexp.
    /// </summary>
    [TestMethod]
    public void ScanComplementaryPerlClassMatchesMalformedUtf8()
    {
        SecretRule rule = SecretRule.Create("dialect", "Dialect test", @"\W");
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            new byte[] { 0xFF },
            "input.txt",
            rules,
            maxDecodeDepth: 0));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("\uFFFD", finding.Match);
        Assert.AreEqual("\uFFFD", finding.Secret);
        Assert.AreEqual("\uFFFD", finding.Line);
        Assert.AreEqual(1, finding.StartLine);
        Assert.AreEqual(1, finding.EndLine);
        Assert.AreEqual(1, finding.StartColumn);
        Assert.AreEqual(1, finding.EndColumn);
        Assert.AreEqual(0, finding.Entropy);
    }

    /// <summary>
    /// Verifies malformed UTF-8 normalization maps matches back to the original line and byte position.
    /// </summary>
    [TestMethod]
    public void ScanMapsMalformedUtf8MatchToOriginalPosition()
    {
        const string replacement = "\uFFFD";
        SecretRule rule = SecretRule.Create("dialect", "Dialect test", replacement);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));
        byte[] input = [(byte)'a', (byte)'\n', 0xFF, (byte)'Z'];

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            input,
            "input.txt",
            rules,
            maxDecodeDepth: 0));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual(replacement, finding.Secret);
        Assert.AreEqual(string.Concat(replacement, "Z"), finding.Line);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual(2, finding.EndLine);
        Assert.AreEqual(2, finding.StartColumn);
        Assert.AreEqual(2, finding.EndColumn);
    }

    private static IReadOnlyList<Finding> Scan(string pattern, string input)
    {
        SecretRule rule = SecretRule.Create("dialect", "Dialect test", pattern);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));
        return SecretScanner.Scan(new ScanRequest(Encoding.UTF8.GetBytes(input), "input.txt", rules, maxDecodeDepth: 0));
    }
}
