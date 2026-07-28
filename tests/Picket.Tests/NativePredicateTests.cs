using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using Scout.Text.Regex;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests bounded native source and finding predicates.
/// </summary>
[TestClass]
public sealed class NativePredicateTests
{
    /// <summary>
    /// Verifies a global prefilter suppresses a native source without affecting strict scans.
    /// </summary>
    [TestMethod]
    public void GlobalPrefilterAppliesOnlyWhenNativePredicatesAreEnabled()
    {
        CompiledRuleSet rules = Compile(
            prefilter: "source.path ends_with \".md\"");
        byte[] input = Encoding.UTF8.GetBytes("token-example");

        IReadOnlyList<Finding> nativeFindings = Scan(
            input,
            "docs/example.md",
            rules,
            enableNativePredicates: true);
        IReadOnlyList<Finding> strictFindings = Scan(
            input,
            "docs/example.md",
            rules,
            enableNativePredicates: false);

        Assert.IsEmpty(nativeFindings);
        Assert.HasCount(1, strictFindings);
        Assert.AreEqual("token-example", strictFindings[0].Secret);
    }

    /// <summary>
    /// Verifies a global prefilter can skip a source before a deferred rule regex is compiled.
    /// </summary>
    [TestMethod]
    public void GlobalPrefilterRunsBeforeDeferredRegexCompilation()
    {
        SecretRule invalidRule = SecretRule.Create(
            "invalid",
            "Invalid deferred regex",
            "[");
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet(
            [invalidRule],
            regexesPrevalidated: true,
            prefilter: "source.path == \"skip.txt\""));
        byte[] input = Encoding.UTF8.GetBytes("token-example");

        IReadOnlyList<Finding> nativeFindings = Scan(
            input,
            "skip.txt",
            rules,
            enableNativePredicates: true);

        Assert.IsEmpty(nativeFindings);
        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(
            () => Scan(
                input,
                "skip.txt",
                rules,
                enableNativePredicates: false));
        Assert.IsInstanceOfType<ByteRegexParseException>(exception.InnerException);
    }

    /// <summary>
    /// Verifies source symlink metadata is available to prefilters.
    /// </summary>
    [TestMethod]
    public void GlobalPrefilterEvaluatesSourceSymlink()
    {
        CompiledRuleSet rules = Compile(
            prefilter: "source.symlink == \"linked-secret.txt\"");
        byte[] input = Encoding.UTF8.GetBytes("token-example");

        IReadOnlyList<Finding> skipped = Scan(
            input,
            "secret.txt",
            rules,
            enableNativePredicates: true,
            symlinkFile: "linked-secret.txt");
        IReadOnlyList<Finding> retained = Scan(
            input,
            "secret.txt",
            rules,
            enableNativePredicates: true,
            symlinkFile: "other-link.txt");

        Assert.IsEmpty(skipped);
        Assert.HasCount(1, retained);
    }

    /// <summary>
    /// Verifies a rule prefilter skips only its owning rule.
    /// </summary>
    [TestMethod]
    public void RulePrefilterSkipsOnlyOwningRule()
    {
        SecretRule filteredRule = CreateRule(
            "filtered",
            prefilter: "source.path starts_with \"tests/\"");
        SecretRule retainedRule = CreateRule("retained");
        CompiledRuleSet rules = CompiledRuleSet.Compile(
            new RuleSet([filteredRule, retainedRule]));

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("token-example"),
            "tests/fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(1, findings);
        Assert.AreEqual("retained", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies a rule filter suppresses only candidates produced by its owning rule.
    /// </summary>
    [TestMethod]
    public void RuleFilterSuppressesOnlyOwningRule()
    {
        SecretRule filteredRule = CreateRule(
            "filtered",
            filter: "finding.secret == \"token-example\"");
        SecretRule retainedRule = CreateRule("retained");
        CompiledRuleSet rules = CompiledRuleSet.Compile(
            new RuleSet([filteredRule, retainedRule]));

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("token-example"),
            "fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(1, findings);
        Assert.AreEqual("retained", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies filtered supporting evidence cannot satisfy a required-rule correlation.
    /// </summary>
    [TestMethod]
    public void NativeFilterRunsBeforeRequiredRuleCorrelation()
    {
        byte[] input = Encoding.UTF8.GetBytes(
            "username=\"alice\"\npassword=\"secret\"");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "primary-rule",
                "Primary rule",
                "password=\"([^\"]+)\"",
                requiredRules: [new SecretRequiredRule("username-rule")]),
            SecretRule.Create(
                "username-rule",
                "Username rule",
                "username=\"([^\"]+)\"",
                skipReport: true,
                filter: "true"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> nativeFindings = Scan(
            input,
            "config.txt",
            rules,
            enableNativePredicates: true);
        IReadOnlyList<Finding> strictFindings = Scan(
            input,
            "config.txt",
            rules,
            enableNativePredicates: false);

        Assert.IsEmpty(nativeFindings);
        Assert.HasCount(1, strictFindings);
        Assert.HasCount(1, strictFindings[0].RequiredFindings);
    }

    /// <summary>
    /// Verifies global post-match filters can combine source and finding fields.
    /// </summary>
    [TestMethod]
    public void GlobalFilterSuppressesOnlyMatchingCandidates()
    {
        CompiledRuleSet rules = Compile(
            filter: """
                source.path starts_with "tests/" &&
                finding.secret == "token-example"
                """);
        byte[] input = Encoding.UTF8.GetBytes("token-example token-production");

        IReadOnlyList<Finding> findings = Scan(
            input,
            "tests/fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(1, findings);
        Assert.AreEqual("token-production", findings[0].Secret);
    }

    /// <summary>
    /// Verifies finding predicates expose documented scalar, list, and rule metadata fields.
    /// </summary>
    [TestMethod]
    public void RuleFilterEvaluatesDocumentedFindingFields()
    {
        SecretRule rule = CreateRule(
            "metadata",
            tags: ["cloud", "token"],
            provider: "GitHub",
            severity: "high",
            confidence: "medium",
            rulePack: "picket-test",
            filter: """
                finding.rule_id == "metadata" &&
                finding.description contains "Token" &&
                finding.match starts_with "token-" &&
                finding.line ends_with "example" &&
                finding.start_line == 1 &&
                finding.end_line == 1 &&
                finding.start_column == 1 &&
                finding.end_column > finding.start_column &&
                finding.entropy >= 0 &&
                finding.randomness_score >= 0 &&
                finding.decode_depth == 0 &&
                !finding.is_decoded &&
                finding.tags contains "cloud" &&
                finding.severity == "high" &&
                finding.confidence == "medium" &&
                finding.rule_pack == "picket-test" &&
                finding.provider == "GitHub" &&
                finding.secret matches "^token-[a-z]+$"
                """);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("token-example"),
            "fixture.txt",
            rules,
            enableNativePredicates: true,
            enableRandomnessScoring: true);

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies decoded findings expose their decode path and depth.
    /// </summary>
    [TestMethod]
    public void RuleFilterEvaluatesDecodeMetadata()
    {
        SecretRule rule = CreateRule(
            "decoded",
            filter: """
                finding.is_decoded &&
                finding.decode_depth == 1 &&
                finding.decode_path contains "base64"
                """);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("encoded=dG9rZW4tZXhhbXBsZQ=="),
            "fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies typed operators, precedence, parentheses, negation, and ordinal string comparison.
    /// </summary>
    [TestMethod]
    [DataRow("\"alpha\" != \"beta\"", 0)]
    [DataRow("1 < 2", 0)]
    [DataRow("2 <= 2", 0)]
    [DataRow("3 > 2", 0)]
    [DataRow("3 >= 3", 0)]
    [DataRow("\"alphabet\" contains \"pha\"", 0)]
    [DataRow("\"alphabet\" starts_with \"alpha\"", 0)]
    [DataRow("\"alphabet\" ends_with \"bet\"", 0)]
    [DataRow("false || true && true", 0)]
    [DataRow("(false || true) && !false", 0)]
    [DataRow("\"Alpha\" == \"alpha\"", 1)]
    public void PredicateOperatorsUseTypedOrdinalSemantics(
        string expression,
        int expectedFindingCount)
    {
        CompiledRuleSet rules = Compile(filter: expression);

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("token-example"),
            "fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(expectedFindingCount, findings);
    }

    /// <summary>
    /// Verifies boolean operators short-circuit before an over-budget dynamic value is evaluated.
    /// </summary>
    [TestMethod]
    public void BooleanOperatorsShortCircuit()
    {
        string oversizedSecret = string.Concat("token-", new string('x', 65_537));
        byte[] input = Encoding.UTF8.GetBytes(oversizedSecret);
        CompiledRuleSet suppressingRules = Compile(
            filter: "true || finding.secret contains \"never\"");
        CompiledRuleSet retainingRules = Compile(
            filter: "false && finding.secret contains \"token\"");

        IReadOnlyList<Finding> suppressed = Scan(
            input,
            "fixture.txt",
            suppressingRules,
            enableNativePredicates: true);
        IReadOnlyList<Finding> retained = Scan(
            input,
            "fixture.txt",
            retainingRules,
            enableNativePredicates: true);

        Assert.IsEmpty(suppressed);
        Assert.HasCount(1, retained);
        Assert.AreEqual(oversizedSecret, retained[0].Secret);
    }

    /// <summary>
    /// Verifies over-budget dynamic string operands retain the finding instead of suppressing it.
    /// </summary>
    [TestMethod]
    [DataRow("finding.secret contains \"token\"")]
    [DataRow("finding.secret starts_with \"token\"")]
    [DataRow("finding.secret ends_with \"x\"")]
    [DataRow("finding.secret matches \"^token-\"")]
    public void RuntimeStringLimitFailsOpen(string expression)
    {
        string oversizedSecret = string.Concat("token-", new string('x', 65_537));
        CompiledRuleSet rules = Compile(filter: expression);

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes(oversizedSecret),
            "fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(1, findings);
        Assert.AreEqual(oversizedSecret, findings[0].Secret);
    }

    /// <summary>
    /// Verifies an over-budget list retains the finding instead of suppressing it.
    /// </summary>
    [TestMethod]
    public void RuntimeListLimitFailsOpen()
    {
        string[] tags = [.. Enumerable.Range(0, 257).Select(
            static index => $"tag-{index}")];
        SecretRule rule = CreateRule(
            "many-tags",
            tags: tags,
            filter: "finding.tags contains \"tag-0\"");
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet([rule]));

        IReadOnlyList<Finding> findings = Scan(
            Encoding.UTF8.GetBytes("token-example"),
            "fixture.txt",
            rules,
            enableNativePredicates: true);

        Assert.HasCount(1, findings);
    }

    /// <summary>
    /// Verifies malformed native predicates are ignored when native evaluation is disabled.
    /// </summary>
    [TestMethod]
    public void StrictScanDoesNotCompileNativePredicate()
    {
        CompiledRuleSet rules = Compile(
            filter: "environment.secret == \"value\"");
        byte[] input = Encoding.UTF8.GetBytes("token-example");

        IReadOnlyList<Finding> findings = Scan(
            input,
            "fixture.txt",
            rules,
            enableNativePredicates: false);

        Assert.HasCount(1, findings);
        Assert.ThrowsExactly<InvalidDataException>(
            rules.ValidateNativePredicates);
    }

    /// <summary>
    /// Verifies invalid syntax, fields, types, and regexes fail predicate validation.
    /// </summary>
    [TestMethod]
    [DataRow("finding.secret == \"value\"", true, "not available to prefilters")]
    [DataRow("source.unknown == \"value\"", false, "unknown field")]
    [DataRow("finding.secret && true", false, "must produce a boolean")]
    [DataRow("finding.start_line contains \"1\"", false, "does not accept")]
    [DataRow("finding.secret matches source.path", false, "string literal regex")]
    [DataRow("finding.secret matches \"[\"", false, "invalid 'matches' regex")]
    [DataRow("finding.tags == finding.decode_path", false, "does not accept")]
    public void PredicateValidationRejectsInvalidExpressions(
        string expression,
        bool prefilter,
        string expectedMessage)
    {
        CompiledRuleSet rules = prefilter
            ? Compile(prefilter: expression)
            : Compile(filter: expression);

        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(
            rules.ValidateNativePredicates);

        Assert.Contains(expectedMessage, exception.Message);
        Assert.Contains("column", exception.Message);
    }

    /// <summary>
    /// Verifies compile-time predicate resource limits reject oversized input.
    /// </summary>
    [TestMethod]
    public void PredicateValidationEnforcesResourceLimits()
    {
        string oversizedExpression = new('x', 4097);
        string oversizedUtf8Expression = string.Concat("true ", new string('\u0800', 1365));
        string oversizedLiteral = string.Concat(
            "finding.secret == \"",
            new string('x', 1025),
            "\"");
        string oversizedUtf8Literal = string.Concat(
            "finding.secret == \"",
            new string('\u0800', 342),
            "\"");
        string excessiveNesting = string.Concat(
            new string('(', 17),
            "true",
            new string(')', 17));
        string excessiveTokens = string.Join(
            " || ",
            Enumerable.Repeat("false", 129));
        string excessiveRegexes = string.Join(
            " || ",
            Enumerable.Repeat("finding.secret matches \"x\"", 33));

        AssertValidationFails(oversizedExpression, "4096-byte");
        AssertValidationFails(oversizedUtf8Expression, "4096-byte");
        AssertValidationFails(oversizedLiteral, "string literal exceeds 1024");
        AssertValidationFails(oversizedUtf8Literal, "string literal exceeds 1024");
        AssertValidationFails(excessiveNesting, "nesting exceeds 16");
        AssertValidationFails(excessiveTokens, "token count exceeds 256");
        AssertValidationFails(excessiveRegexes, "regex count exceeds 32");
    }

    /// <summary>
    /// Verifies predicate compilation accepts values exactly at each reachable resource boundary.
    /// </summary>
    [TestMethod]
    public void PredicateValidationAcceptsResourceBoundaries()
    {
        string maximumExpression = string.Concat("true", new string(' ', 4092));
        string maximumLiteral = string.Concat(
            "finding.secret == \"",
            new string('x', 1024),
            "\"");
        string maximumNesting = string.Concat(
            new string('(', 16),
            "true",
            new string(')', 16));
        string maximumTokens = string.Join(
            " || ",
            Enumerable.Repeat("false", 128));
        string maximumRegexes = string.Join(
            " || ",
            Enumerable.Repeat("finding.secret matches \"x\"", 32));

        CompileAndValidate(maximumExpression);
        CompileAndValidate(maximumLiteral);
        CompileAndValidate(maximumNesting);
        CompileAndValidate(maximumTokens);
        CompileAndValidate(maximumRegexes);
    }

    /// <summary>
    /// Verifies concurrent native scans safely share first-use predicate compilation.
    /// </summary>
    [TestMethod]
    public void PredicatesSupportConcurrentFirstUse()
    {
        const int ScanCount = 64;
        CompiledRuleSet rules = Compile(
            filter: "finding.secret == \"token-example\"");
        byte[] input = Encoding.UTF8.GetBytes("token-example");
        var findingCounts = new int[ScanCount];

        Parallel.For(0, ScanCount, index =>
        {
            findingCounts[index] = Scan(
                input,
                "fixture.txt",
                rules,
                enableNativePredicates: true).Count;
        });

        Assert.DoesNotContain(static count => count != 0, findingCounts);
    }

    /// <summary>
    /// Verifies predicates participate in rule-set identity and cache address selection.
    /// </summary>
    [TestMethod]
    public void PredicatesChangeFingerprintAndRequirePathAddressing()
    {
        CompiledRuleSet unfiltered = Compile();
        CompiledRuleSet filtered = Compile(
            filter: "source.path ends_with \".md\"");

        Assert.AreNotEqual(unfiltered.Fingerprint, filtered.Fingerprint);
        Assert.IsFalse(unfiltered.UsesPathSensitiveMatching);
        Assert.IsTrue(filtered.UsesPathSensitiveMatching);
    }

    /// <summary>
    /// Verifies global and rule predicates survive multiline TOML load and deterministic output.
    /// </summary>
    [TestMethod]
    public void ConfigRoundTripPreservesPredicates()
    {
        const string Toml = """
            prefilter = '''
            source.path ends_with ".md" ||
            source.symlink != ""
            '''
            filter = 'finding.provider == "Example"'

            [[rules]]
            id = "token"
            description = "Token"
            regex = '''token-[a-z]+'''
            prefilter = 'source.path starts_with "vendor/"'
            filter = 'finding.secret == "token-example"'
            """;

        RuleSet loaded = GitleaksConfigLoader.FromToml(Toml, "memory");
        string written = GitleaksConfigWriter.Write(loaded);
        RuleSet reloaded = GitleaksConfigLoader.FromToml(written, "written");

        Assert.Contains("source.path ends_with \".md\"", loaded.Prefilter);
        Assert.Contains("source.symlink != \"\"", loaded.Prefilter);
        Assert.AreEqual("finding.provider == \"Example\"", loaded.Filter);
        Assert.HasCount(1, loaded.Rules);
        Assert.AreEqual(
            "source.path starts_with \"vendor/\"",
            loaded.Rules[0].Prefilter);
        Assert.AreEqual(
            "finding.secret == \"token-example\"",
            loaded.Rules[0].Filter);
        Assert.AreEqual(loaded.Prefilter, reloaded.Prefilter);
        Assert.AreEqual(loaded.Filter, reloaded.Filter);
        Assert.AreEqual(loaded.Rules[0].Prefilter, reloaded.Rules[0].Prefilter);
        Assert.AreEqual(loaded.Rules[0].Filter, reloaded.Rules[0].Filter);
    }

    /// <summary>
    /// Verifies config extension inherits predicates and explicit empty values clear inherited predicates.
    /// </summary>
    [TestMethod]
    public void ConfigExtensionInheritsAndClearsPredicates()
    {
        using TempDirectory root = TempDirectory.Create();
        string basePath = Path.Combine(root.Path, "base.toml");
        string inheritedPath = Path.Combine(root.Path, "inherited.toml");
        string clearedPath = Path.Combine(root.Path, "cleared.toml");
        File.WriteAllText(
            basePath,
            """
            prefilter = 'source.path starts_with "vendor/"'
            filter = 'finding.provider == "Example"'

            [[rules]]
            id = "token"
            description = "Token"
            regex = '''token-[a-z]+'''
            prefilter = 'source.path ends_with ".md"'
            filter = 'finding.secret == "token-example"'
            """);
        File.WriteAllText(
            inheritedPath,
            $"""
            [extend]
            path = '{basePath}'
            """);
        File.WriteAllText(
            clearedPath,
            $"""
            prefilter = ''
            filter = ''

            [extend]
            path = '{basePath}'

            [[rules]]
            id = "token"
            prefilter = ''
            filter = ''
            """);

        RuleSet inherited = GitleaksConfigLoader.LoadFile(inheritedPath);
        RuleSet cleared = GitleaksConfigLoader.LoadFile(clearedPath);

        Assert.AreEqual(
            "source.path starts_with \"vendor/\"",
            inherited.Prefilter);
        Assert.AreEqual(
            "finding.provider == \"Example\"",
            inherited.Filter);
        Assert.AreEqual(
            "source.path ends_with \".md\"",
            inherited.Rules[0].Prefilter);
        Assert.AreEqual(
            "finding.secret == \"token-example\"",
            inherited.Rules[0].Filter);
        Assert.IsEmpty(cleared.Prefilter);
        Assert.IsEmpty(cleared.Filter);
        Assert.IsEmpty(cleared.Rules[0].Prefilter);
        Assert.IsEmpty(cleared.Rules[0].Filter);
    }

    private static void AssertValidationFails(
        string expression,
        string expectedMessage)
    {
        CompiledRuleSet rules = Compile(filter: expression);

        InvalidDataException exception = Assert.ThrowsExactly<InvalidDataException>(
            rules.ValidateNativePredicates);

        Assert.Contains(expectedMessage, exception.Message);
    }

    private static void CompileAndValidate(string expression)
    {
        CompiledRuleSet rules = Compile(filter: expression);

        rules.ValidateNativePredicates();
    }

    private static CompiledRuleSet Compile(
        string prefilter = "",
        string filter = "")
    {
        return CompiledRuleSet.Compile(new RuleSet(
            [CreateRule("token")],
            prefilter: prefilter,
            filter: filter));
    }

    private static SecretRule CreateRule(
        string id,
        IReadOnlyList<string>? tags = null,
        string provider = "",
        string severity = "",
        string confidence = "",
        string rulePack = "",
        string prefilter = "",
        string filter = "")
    {
        return SecretRule.Create(
            id,
            "Token rule",
            "token-[a-z]+",
            tags: tags,
            provider: provider,
            severity: severity,
            confidence: confidence,
            rulePack: rulePack,
            prefilter: prefilter,
            filter: filter);
    }

    private static IReadOnlyList<Finding> Scan(
        byte[] input,
        string fileName,
        CompiledRuleSet rules,
        bool enableNativePredicates,
        bool enableRandomnessScoring = false,
        string symlinkFile = "")
    {
        return SecretScanner.Scan(new ScanRequest(
            input,
            fileName,
            rules,
            symlinkFile: symlinkFile)
        {
            EnableNativePredicates = enableNativePredicates,
            EnableRandomnessScoring = enableRandomnessScoring,
            PositionKind = FindingPositionKind.UnicodeCodePointsExclusive,
        });
    }
}
