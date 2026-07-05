using System.Text;
using Picket.Compat;
using Picket.Engine;
using Picket.Rules;

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
    /// Verifies that reported columns after a newline match Gitleaks' compatibility location model.
    /// </summary>
    [TestMethod]
    public void ScanUsesGitleaksCompatibleColumnsAfterNewline()
    {
        byte[] input = Encoding.UTF8.GetBytes("old = \"token-11111\"\nnew = \"token-22222\"");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(2, findings);
        Assert.AreEqual(8, findings[0].StartColumn);
        Assert.AreEqual(18, findings[0].EndColumn);
        Assert.AreEqual(9, findings[1].StartColumn);
        Assert.AreEqual(19, findings[1].EndColumn);
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
    [Timeout(5000, CooperativeCancellation = true)]
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
    /// Verifies that native AWS pair detection reports a nearby labeled secret access key.
    /// </summary>
    [TestMethod]
    public void ScanFindsNativeAwsAccessKeyPair()
    {
        string accessKeyId = CreateAwsAccessKeyId();
        string secretAccessKey = CreateAwsSecretAccessKey();
        byte[] input = Encoding.UTF8.GetBytes($"aws_access_key_id = {accessKeyId}\naws_secret_access_key = {secretAccessKey}\n");
        CompiledRuleSet rules = CompileAwsCredentialPairRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "credentials.ini", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("picket-aws-access-key-pair", finding.RuleID);
        Assert.Contains(accessKeyId, finding.Match);
        Assert.AreEqual(secretAccessKey, finding.Secret);
        Assert.AreEqual("credentials.ini:picket-aws-access-key-pair:1", finding.Fingerprint);
    }

    /// <summary>
    /// Verifies that native AWS pair detection requires a labeled secret access key near the access key ID.
    /// </summary>
    [TestMethod]
    public void ScanSkipsNativeAwsAccessKeyPairWhenSecretIsUnlabeled()
    {
        string accessKeyId = CreateAwsAccessKeyId();
        string secretAccessKey = CreateAwsSecretAccessKey();
        byte[] input = Encoding.UTF8.GetBytes($"aws_access_key_id = {accessKeyId}\nunrelated = {secretAccessKey}\n");
        CompiledRuleSet rules = CompileAwsCredentialPairRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "credentials.ini", rules));

        Assert.IsEmpty(findings);
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

    /// <summary>
    /// Verifies that base64 decoded findings report decoded text with original source locations.
    /// </summary>
    [TestMethod]
    public void ScanFindsBase64EncodedSecretWithOriginalLocation()
    {
        byte[] input = Encoding.UTF8.GetBytes("before\nencoded=dG9rZW4tMTIzNDU=\nafter\n");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("token-12345", finding.Secret);
        Assert.AreEqual("token-12345", finding.Match);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual("encoded=dG9rZW4tMTIzNDU=", finding.Line);
        Assert.AreEqual("secret.txt:token:2", finding.Fingerprint);
        Assert.Contains("decoded:base64", finding.Tags);
        Assert.Contains("decode-depth:1", finding.Tags);
    }

    /// <summary>
    /// Verifies that long non-decoding base64-like tokens do not cause repeated decoder probes.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public void ScanSkipsLongNonDecodingBase64LikeToken()
    {
        byte[] input = Encoding.UTF8.GetBytes(new string('a', 100_000) + "\nencoded=dG9rZW4tMTIzNDU=\n");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("token-12345", finding.Secret);
        Assert.AreEqual("encoded=dG9rZW4tMTIzNDU=", finding.Line);
        Assert.Contains("decoded:base64", finding.Tags);
    }

    /// <summary>
    /// Verifies that Unicode code point encoded findings report decoded text with original source locations.
    /// </summary>
    [TestMethod]
    public void ScanFindsUnicodeCodePointEncodedSecretWithOriginalLocation()
    {
        byte[] input = Encoding.UTF8.GetBytes(
            "before\nencoded=U+0074 U+006f U+006b U+0065 U+006e U+002d U+0031 U+0032 U+0033 U+0034 U+0035\nafter\n");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("token-12345", finding.Secret);
        Assert.AreEqual("token-12345", finding.Match);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual(
            "encoded=U+0074 U+006f U+006b U+0065 U+006e U+002d U+0031 U+0032 U+0033 U+0034 U+0035",
            finding.Line);
        Assert.AreEqual("secret.txt:token:2", finding.Fingerprint);
        Assert.Contains("decoded:unicode", finding.Tags);
        Assert.Contains("decode-depth:1", finding.Tags);
    }

    /// <summary>
    /// Verifies that Unicode escape encoded findings report decoded text with original source locations.
    /// </summary>
    [TestMethod]
    public void ScanFindsUnicodeEscapeEncodedSecretWithOriginalLocation()
    {
        byte[] input = Encoding.UTF8.GetBytes(
            """
            before
            encoded=\\u0074\\u006f\\u006b\\u0065\\u006e\\u002d\\u0031\\u0032\\u0033\\u0034\\u0035
            after
            """);
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules));

        Assert.HasCount(1, findings);
        Finding finding = findings[0];
        Assert.AreEqual("token-12345", finding.Secret);
        Assert.AreEqual("token-12345", finding.Match);
        Assert.AreEqual(2, finding.StartLine);
        Assert.AreEqual(
            "encoded=\\\\u0074\\\\u006f\\\\u006b\\\\u0065\\\\u006e\\\\u002d\\\\u0031\\\\u0032\\\\u0033\\\\u0034\\\\u0035",
            finding.Line);
        Assert.Contains("decoded:unicode", finding.Tags);
        Assert.Contains("decode-depth:1", finding.Tags);
    }

    /// <summary>
    /// Verifies that the max-target byte cap skips content regex rules.
    /// </summary>
    [TestMethod]
    public void ScanHonorsMaxTargetBytesForContentRules()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-12345");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, maxTargetBytes: input.Length - 1));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that the max-target byte cap does not suppress path-only rules.
    /// </summary>
    [TestMethod]
    public void ScanKeepsPathOnlyRulesWhenMaxTargetBytesIsExceeded()
    {
        byte[] input = Encoding.UTF8.GetBytes("oversized content");
        RuleSet sourceRules = new([
            SecretRule.Create(
                "path-secret",
                "Path Secret",
                string.Empty,
                pathPattern: @"secret\.txt$"),
        ]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(sourceRules);

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, maxTargetBytes: input.Length - 1));

        Assert.HasCount(1, findings);
        Assert.AreEqual("path-secret", findings[0].RuleID);
        Assert.AreEqual("file detected: secret.txt", findings[0].Match);
    }

    /// <summary>
    /// Verifies that symlink paths flow into findings without changing fingerprints.
    /// </summary>
    [TestMethod]
    public void ScanIncludesSymlinkFileInFindings()
    {
        byte[] input = Encoding.UTF8.GetBytes("token-12345");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "target.txt", rules, symlinkFile: "link.txt"));

        Assert.HasCount(1, findings);
        Assert.AreEqual("target.txt", findings[0].File);
        Assert.AreEqual("link.txt", findings[0].SymlinkFile);
        Assert.AreEqual("target.txt:token:1", findings[0].Fingerprint);
    }

    /// <summary>
    /// Verifies that recursive decoding honors the configured maximum depth.
    /// </summary>
    [TestMethod]
    public void ScanHonorsMaxDecodeDepth()
    {
        byte[] input = Encoding.UTF8.GetBytes("encoded=%64%47%39%72%5a%57%34%74%4d%54%49%7a%4e%44%55%3d");
        CompiledRuleSet rules = CompileTokenRule();

        IReadOnlyList<Finding> shallowFindings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, maxDecodeDepth: 1));
        IReadOnlyList<Finding> recursiveFindings = SecretScanner.Scan(new ScanRequest(input, "secret.txt", rules, maxDecodeDepth: 2));

        Assert.IsEmpty(shallowFindings);
        Assert.HasCount(1, recursiveFindings);
        Finding finding = recursiveFindings[0];
        Assert.AreEqual("token-12345", finding.Secret);
        Assert.Contains("decoded:percent", finding.Tags);
        Assert.Contains("decoded:base64", finding.Tags);
        Assert.Contains("decode-depth:2", finding.Tags);
        Assert.HasCount(2, finding.DecodePath);
        Assert.AreEqual("percent", finding.DecodePath[0]);
        Assert.AreEqual("base64", finding.DecodePath[1]);
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

    private static CompiledRuleSet CompileAwsCredentialPairRule()
    {
        return CompiledRuleSet.Compile(new RuleSet([
            SecretRule.Create(
                "picket-aws-access-key-pair",
                "Detected an AWS access key ID paired with a secret access key.",
                "(?i)(?:aws[_ -]?access[_ -]?key[_ -]?id|secret[_ -]?access[_ -]?key)",
                entropy: 4.25,
                keywords: ["akia", "aws_secret_access_key"]),
        ]));
    }

    private static string CreateAwsAccessKeyId()
    {
        return string.Concat("AKIA", "XYZDQCEN4B6JSJQI");
    }

    private static string CreateAwsSecretAccessKey()
    {
        return string.Concat("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
    }
}
