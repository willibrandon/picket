using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="SecretScanner" />.
/// </summary>
[TestClass]
public sealed class SecretScannerTests
{
    /// <summary>
    /// Verifies that the bootstrap scanner detects an AWS access key from byte input.
    /// </summary>
    [TestMethod]
    public void ScanFindsAwsAccessTokenInByteInput()
    {
        byte[] input = Encoding.UTF8.GetBytes("before\nAWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nafter\n");

        CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("aws-access-token", finding.RuleID);
        Assert.AreEqual("AKIA1234567890ABCDEF", finding.Secret);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual("stdin:aws-access-token:2", finding.Fingerprint);
    }

    /// <summary>
    /// Verifies that non-matching input returns no findings.
    /// </summary>
    [TestMethod]
    public void ScanReturnsEmptyWhenNoRuleMatches()
    {
        byte[] input = Encoding.UTF8.GetBytes("no secrets here");

        CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that the Gitleaks generic API key rule uses a deterministic matcher instead of a pathological regex path.
    /// </summary>
    [TestMethod]
    [Timeout(5000)]
    public void ScanHandlesGitleaksGenericApiKeyRule()
    {
        byte[] input = Encoding.UTF8.GetBytes("picket_key = abc123def456ghi7890");
        RuleSet sourceRules = GitleaksConfigLoader.FromToml(
            """
            [[rules]]
            id = "generic-api-key"
            description = "Generic API Key"
            regex = '''(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)'''
            entropy = 3.5
            keywords = ["key"]
            """,
            "memory");
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("generic-api-key", findings[0].RuleID);
        Assert.AreEqual("abc123def456ghi7890", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that a missing keyword prevents regex execution for keyword-scoped rules.
    /// </summary>
    [TestMethod]
    public void ScanSkipsRulesWhenKeywordsAreMissing()
    {
        byte[] input = Encoding.UTF8.GetBytes("secret-value");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "keyword-gated",
                "Keyword gated",
                "secret-[a-z]+",
                keywords: ["missing"]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that keyword matching is ASCII case-insensitive.
    /// </summary>
    [TestMethod]
    public void ScanMatchesKeywordsCaseInsensitively()
    {
        byte[] input = Encoding.UTF8.GetBytes("secret-value");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "keyword-gated",
                "Keyword gated",
                "secret-[a-z]+",
                keywords: ["SECRET"]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("keyword-gated", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies that rules without keywords still run.
    /// </summary>
    [TestMethod]
    public void ScanRunsRulesWithoutKeywords()
    {
        byte[] input = Encoding.UTF8.GetBytes("nokey-123");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "no-keyword",
                "No keyword",
                "nokey-[0-9]+"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("no-keyword", findings[0].RuleID);
    }

    /// <summary>
    /// Verifies that entropy uses Gitleaks' strict greater-than threshold.
    /// </summary>
    [TestMethod]
    public void ScanSuppressesSecretsAtEntropyThreshold()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-abcdef12");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "entropy-gated",
                "Entropy gated",
                "token-([a-z0-9]+)",
                secretGroup: 1,
                entropy: 3),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that secrets above the configured entropy threshold are reported.
    /// </summary>
    [TestMethod]
    public void ScanReportsSecretsAboveEntropyThreshold()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-abcdef12");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "entropy-gated",
                "Entropy gated",
                "token-([a-z0-9]+)",
                secretGroup: 1,
                entropy: 2.9),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("abcdef12", findings[0].Secret);
        Assert.AreEqual(3, findings[0].Entropy);
    }

    /// <summary>
    /// Verifies that path-scoped rules scan only matching file paths.
    /// </summary>
    [TestMethod]
    public void ScanAppliesRulePathFilter()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-abcdef12");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "path-scoped",
                "Path scoped",
                "token-([a-z0-9]+)",
                secretGroup: 1,
                pathPattern: @"\.py$"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> skipped = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));
        IReadOnlyList<Finding> matched = SecretScanner.Scan(new ScanRequest(input, "secret.py", rules));

        Assert.IsEmpty(skipped);
        Assert.HasCount(1, matched);
        Assert.AreEqual("secret.py", matched[0].File);
    }

    /// <summary>
    /// Verifies that path-only rules create file findings without content regex matches.
    /// </summary>
    [TestMethod]
    public void ScanReportsPathOnlyRule()
    {
        RuleSet sourceRules = new([
            SecretRule.Create(
                "python-files-only",
                "Python Files",
                string.Empty,
                pathPattern: ".py"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(ReadOnlyMemory<byte>.Empty, "tmp.py", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("python-files-only", findings[0].RuleID);
        Assert.AreEqual("file detected: tmp.py", findings[0].Match);
        Assert.AreEqual(string.Empty, findings[0].Secret);
        Assert.AreEqual("tmp.py:python-files-only:0", findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that skipReport rules suppress normal findings.
    /// </summary>
    [TestMethod]
    public void ScanSuppressesSkipReportRules()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-1234");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "supporting-rule",
                "Supporting Rule",
                "token-[0-9]+",
                skipReport: true),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that required supporting rules enable composite findings.
    /// </summary>
    [TestMethod]
    public void ScanReportsFindingWhenRequiredRuleMatches()
    {
        byte[] input = Encoding.UTF8.GetBytes("username=\"alice\"\npassword=\"secret\"");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "primary-rule",
                "Primary Rule",
                "password=\"([^\"]+)\"",
                requiredRules: [new SecretRequiredRule("username-rule")]),
            SecretRule.Create(
                "username-rule",
                "Username Rule",
                "username=\"([^\"]+)\"",
                skipReport: true),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "config.txt", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("primary-rule", findings[0].RuleID);
        Assert.AreEqual("secret", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that required supporting rules honor line proximity.
    /// </summary>
    [TestMethod]
    public void ScanSuppressesFindingWhenRequiredRuleIsOutsideLineProximity()
    {
        byte[] input = Encoding.UTF8.GetBytes("username=\"alice\"\nother=true\npassword=\"secret\"");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "primary-rule",
                "Primary Rule",
                "password=\"([^\"]+)\"",
                requiredRules: [new SecretRequiredRule("username-rule", withinLines: 1)]),
            SecretRule.Create(
                "username-rule",
                "Username Rule",
                "username=\"([^\"]+)\"",
                skipReport: true),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "config.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that rule path patterns can match Windows separators against normalized paths.
    /// </summary>
    [TestMethod]
    public void ScanMatchesWindowsRulePathSeparator()
    {
        RuleSet sourceRules = new([
            SecretRule.Create(
                "maven-settings",
                "Maven Settings",
                string.Empty,
                pathPattern: @"(^|\\)\.m2\\settings\.xml"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(ReadOnlyMemory<byte>.Empty, ".m2/settings.xml", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual(".m2/settings.xml", findings[0].File);
    }

    /// <summary>
    /// Verifies that an unset secret group reports the first non-empty capture group.
    /// </summary>
    [TestMethod]
    public void ScanUsesFirstCaptureGroupWhenSecretGroupIsUnset()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=ABCD");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "capture-default",
                "Capture default",
                "key=([A-Z]+)"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("key=ABCD", findings[0].Match);
        Assert.AreEqual("ABCD", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that empty or nonparticipating captures are skipped when secret group is unset.
    /// </summary>
    [TestMethod]
    public void ScanSkipsEmptyCaptureGroupsWhenSecretGroupIsUnset()
    {
        byte[] input = Encoding.UTF8.GetBytes("bar");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "capture-default",
                "Capture default",
                "(foo)?(bar)"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("bar", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that inline gitleaks:allow comments suppress same-line findings by default.
    /// </summary>
    [TestMethod]
    public void ScanSuppressesInlineGitleaksAllowByDefault()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=token-1234 // gitleaks:allow");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that inline gitleaks:allow comments can be ignored for compatibility flags.
    /// </summary>
    [TestMethod]
    public void ScanReportsInlineGitleaksAllowWhenIgnored()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=token-1234 // gitleaks:allow");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, ignoreGitleaksAllow: true));

        Assert.HasCount(1, findings);
        Assert.AreEqual("token-1234", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that gitleaks:allow on a different line does not suppress a finding.
    /// </summary>
    [TestMethod]
    public void ScanDoesNotSuppressGitleaksAllowOnDifferentLine()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=token-1234\n// gitleaks:allow");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(1, findings);
        Assert.AreEqual("token-1234", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that per-rule regex allowlists suppress matching findings.
    /// </summary>
    [TestMethod]
    public void ScanAppliesRuleRegexAllowlist()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=AKIALALEMEL33243OLIA");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "aws-access-key",
                "AWS Access Key",
                "AKIA[0-9A-Z]{16}",
                allowlists: [
                    SecretAllowlist.Create(regexPatterns: ["AKIALALEMEL33243OLIA"]),
                ]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that global path allowlists suppress findings from matching files.
    /// </summary>
    [TestMethod]
    public void ScanAppliesGlobalPathAllowlist()
    {
        byte[] input = Encoding.UTF8.GetBytes("key=AKIA1234567890ABCDEF");
        RuleSet sourceRules = new(
            [
                SecretRule.Create(
                    "aws-access-key",
                    "AWS Access Key",
                    "AKIA[0-9A-Z]{16}"),
            ],
            [
                SecretAllowlist.Create(pathPatterns: ["vendor/"]),
            ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "vendor/secret.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that allowlist regexTarget can suppress based on the source line.
    /// </summary>
    [TestMethod]
    public void ScanAppliesAllowlistRegexTargetLine()
    {
        byte[] input = Encoding.UTF8.GetBytes("prefix token-1234 # test fixture");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "token",
                "Token",
                "token-([0-9]+)",
                allowlists: [
                    SecretAllowlist.Create(
                        regexTarget: AllowlistRegexTarget.Line,
                        regexPatterns: ["test fixture"]),
                ]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that AND allowlists require every configured check.
    /// </summary>
    [TestMethod]
    public void ScanRequiresEveryAllowlistCheckForAndCondition()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-1234");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "token",
                "Token",
                "token-([0-9]+)",
                allowlists: [
                    SecretAllowlist.Create(
                        condition: AllowlistCondition.And,
                        pathPatterns: [@"\.txt$"],
                        regexPatterns: ["1234"]),
                ]),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> allowed = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));
        IReadOnlyList<Finding> detected = SecretScanner.Scan(new ScanRequest(input, "secret.py", rules));

        Assert.IsEmpty(allowed);
        Assert.HasCount(1, detected);
    }

    private static CompiledRuleSet CompileTokenRule()
    {
        return CompiledRuleSet.Compile(new RuleSet([
            SecretRule.Create(
                "token",
                "Token",
                "token-[0-9]+"),
        ]));
    }
}
