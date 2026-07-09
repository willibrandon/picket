using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksFindingRedactor" />.
/// </summary>
[TestClass]
public sealed class GitleaksFindingRedactorTests
{
    /// <summary>
    /// Verifies full redaction replaces the secret in both secret and match fields.
    /// </summary>
    [TestMethod]
    public void RedactFullyReplacesSecret()
    {
        Finding finding = CreateFinding("line containing secret", "secret");

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100);

        Assert.AreEqual("REDACTED", redacted.Secret);
        Assert.AreEqual("line containing REDACTED", redacted.Match);
        Assert.AreEqual("line containing REDACTED", redacted.Line);
        Assert.AreEqual("https://github.com/example/repo/blob/commit/secret.txt#L1", redacted.Link);
        Assert.AreEqual("2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b", redacted.SecretSha256);
        Assert.AreEqual("307aa91418c6be9b60a0de3bd843a2e3f206061b0674fc6171ad91025f1c0cb3", redacted.MatchSha256);
    }

    /// <summary>
    /// Verifies partial redaction keeps the same rounding behavior as Gitleaks.
    /// </summary>
    [TestMethod]
    public void RedactPartiallyMasksSecret()
    {
        Finding finding = CreateFinding("line containing secret", "secret");

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 75);

        Assert.AreEqual("se...", redacted.Secret);
        Assert.AreEqual("line containing se...", redacted.Match);
    }

    /// <summary>
    /// Verifies low redaction keeps most of the secret and appends an ellipsis.
    /// </summary>
    [TestMethod]
    public void RedactLowPercentageMasksSecret()
    {
        Finding finding = CreateFinding("line containing secret", "secret");

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 10);

        Assert.AreEqual("secre...", redacted.Secret);
        Assert.AreEqual("line containing secre...", redacted.Match);
    }

    /// <summary>
    /// Verifies native redaction can require non-zero percentages to hide at least one character.
    /// </summary>
    [TestMethod]
    public void RedactStrictNonZeroPercentageMasksAtLeastOneCharacter()
    {
        Finding finding = CreateFinding("abcdefghij", "abcdefghij");

        Finding compatible = GitleaksFindingRedactor.Redact(finding, 5);
        Finding strict = GitleaksFindingRedactor.Redact(finding, 5, requirePartialMask: true);

        Assert.AreEqual("abcdefghij...", compatible.Secret);
        Assert.AreEqual("abcdefghi...", strict.Secret);
        Assert.DoesNotContain("abcdefghij", strict.Secret);
    }

    /// <summary>
    /// Verifies strict native redaction never leaves a full secret visible for non-zero percentages.
    /// </summary>
    [TestMethod]
    public void RedactStrictNonZeroPercentagesNeverKeepFullSecret()
    {
        for (int length = 1; length <= 64; length++)
        {
            string secret = new('a', length);
            Finding finding = CreateFinding(secret, secret);
            for (int redactionPercent = 1; redactionPercent < 100; redactionPercent++)
            {
                Finding redacted = GitleaksFindingRedactor.Redact(finding, redactionPercent, requirePartialMask: true);

                Assert.DoesNotContain(secret, redacted.Secret);
                Assert.DoesNotContain(secret, redacted.Match);
            }
        }
    }

    /// <summary>
    /// Verifies partial redaction handles secrets large enough to overflow unchecked integer percentage math.
    /// </summary>
    [TestMethod]
    public void RedactHandlesVeryLargeSecretWithoutOverflow()
    {
        const int SecretLength = 22_000_000;

        string secret = new('a', SecretLength);
        Finding finding = new(
            "rule",
            "description",
            1,
            1,
            1,
            6,
            "marker",
            secret,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:rule:1",
            "encoded secret",
            secretSha256: new string('0', 64),
            matchSha256: new string('1', 64),
            decodePath: ["base64"]);

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 1);

        int expectedVisibleLength = (int)Math.Round((double)SecretLength * 99 / 100.0, MidpointRounding.ToEven);
        Assert.AreEqual(expectedVisibleLength + 3, redacted.Secret.Length);
        Assert.AreEqual("...", redacted.Secret[^3..]);
        Assert.AreEqual("marker", redacted.Match);
    }

    /// <summary>
    /// Verifies native redaction does not keep hashes of the original evidence.
    /// </summary>
    [TestMethod]
    public void RedactStrictHashesRedactedEvidence()
    {
        Finding finding = CreateFinding("line containing secret", "secret");

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100, requirePartialMask: true);

        Assert.AreEqual(CreateSha256("REDACTED"), redacted.SecretSha256);
        Assert.AreEqual(CreateSha256("line containing REDACTED"), redacted.MatchSha256);
        Assert.AreNotEqual(CreateSha256("secret"), redacted.SecretSha256);
        Assert.AreNotEqual(CreateSha256("line containing secret"), redacted.MatchSha256);
    }

    /// <summary>
    /// Verifies that zero redaction keeps findings unchanged.
    /// </summary>
    [TestMethod]
    public void RedactZeroKeepsFinding()
    {
        Finding finding = CreateFinding("line containing secret", "secret");

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 0);

        Assert.AreSame(finding, redacted);
    }

    /// <summary>
    /// Verifies that empty secrets are not expanded throughout the match text.
    /// </summary>
    [TestMethod]
    public void RedactEmptySecretKeepsFinding()
    {
        Finding finding = CreateFinding("file detected: secret.pem", string.Empty);

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100);

        Assert.AreSame(finding, redacted);
    }

    /// <summary>
    /// Verifies that decoded findings do not keep the recoverable encoded source line after redaction.
    /// </summary>
    [TestMethod]
    public void RedactMasksEncodedLineForDecodedFindings()
    {
        const string secret = "token-12345";
        const string encodedSecret = "dG9rZW4tMTIzNDU=";
        Finding finding = CreateFinding(secret, secret, $"encoded={encodedSecret}", ["base64"]);

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100);
        SecretRule rule = SecretRule.Create("rule", "description", "token-[0-9]+");
        string json = PicketJsonReportWriter.Write([redacted], [rule]);

        Assert.AreEqual("REDACTED", redacted.Line);
        Assert.DoesNotContain(secret, redacted.Line);
        Assert.DoesNotContain(encodedSecret, redacted.Line);
        Assert.DoesNotContain(secret, json);
        Assert.DoesNotContain(encodedSecret, json);
    }

    /// <summary>
    /// Verifies redaction does not keep the first physical line of a multi-line secret.
    /// </summary>
    [TestMethod]
    public void RedactMasksLineWhenSecretSpansMultipleLines()
    {
        const string firstLineSecret = "AAAA";
        const string secondLineSecret = "BBBB";
        string secret = string.Concat(firstLineSecret, '\n', secondLineSecret);
        Finding finding = CreateFinding(
            string.Concat("prefix ", secret, " suffix"),
            secret,
            string.Concat("prefix ", firstLineSecret));
        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100, requirePartialMask: true);
        SecretRule rule = SecretRule.Create("rule", "description", "A+");
        string[] reports =
        [
            PicketJsonReportWriter.Write([redacted], [rule]),
            PicketJsonlReportWriter.Write([redacted], [rule]),
            PicketCsvReportWriter.Write([redacted], [rule]),
            PicketJunitReportWriter.Write([redacted], [rule]),
            PicketHtmlReportWriter.Write([redacted], [rule]),
            PicketGitLabCodeQualityReportWriter.Write([redacted]),
            PicketSarifReportWriter.Write([redacted], [rule]),
            PicketToonReportWriter.Write([redacted], [rule]),
        ];

        Assert.AreEqual("REDACTED", redacted.Line);
        foreach (string report in reports)
        {
            Assert.DoesNotContain(firstLineSecret, report);
            Assert.DoesNotContain(secondLineSecret, report);
            Assert.DoesNotContain(CreateSha256(secret), report);
        }
    }

    /// <summary>
    /// Verifies redaction masks the match field when malformed input prevents string replacement.
    /// </summary>
    [TestMethod]
    public void RedactMasksMatchWhenSecretIsNotAStringSubstring()
    {
        const string secret = "secret";
        const string rawMatchEvidence = "raw-boundary-evidence";
        Finding finding = CreateFinding(rawMatchEvidence, secret, rawMatchEvidence);

        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100, requirePartialMask: true);
        SecretRule rule = SecretRule.Create("rule", "description", "secret");
        string[] reports =
        [
            PicketJsonReportWriter.Write([redacted], [rule]),
            PicketJsonlReportWriter.Write([redacted], [rule]),
            PicketCsvReportWriter.Write([redacted], [rule]),
            PicketJunitReportWriter.Write([redacted], [rule]),
            PicketHtmlReportWriter.Write([redacted], [rule]),
            PicketGitLabCodeQualityReportWriter.Write([redacted]),
            PicketSarifReportWriter.Write([redacted], [rule]),
            PicketToonReportWriter.Write([redacted], [rule]),
        ];

        Assert.AreEqual("REDACTED", redacted.Match);
        Assert.AreEqual("REDACTED", redacted.Line);
        foreach (string report in reports)
        {
            Assert.DoesNotContain(rawMatchEvidence, report);
            Assert.DoesNotContain(CreateSha256(secret), report);
            Assert.DoesNotContain(CreateSha256(rawMatchEvidence), report);
        }
    }

    /// <summary>
    /// Verifies native report writers do not reintroduce raw or encoded secret evidence after redaction.
    /// </summary>
    [TestMethod]
    public void RedactedDecodedFindingLeavesNoSecretInAnyNativeFormat()
    {
        const string secret = "token-12345";
        const string encodedSecret = "dG9rZW4tMTIzNDU=";
        Finding finding = CreateFinding(secret, secret, $"encoded={encodedSecret}", ["base64"]);
        Finding redacted = GitleaksFindingRedactor.Redact(finding, 100, requirePartialMask: true);
        SecretRule rule = SecretRule.Create("rule", "description", "token-[0-9]+");
        string[] reports =
        [
            PicketJsonReportWriter.Write([redacted], [rule]),
            PicketJsonlReportWriter.Write([redacted], [rule]),
            PicketCsvReportWriter.Write([redacted], [rule]),
            PicketJunitReportWriter.Write([redacted], [rule]),
            PicketHtmlReportWriter.Write([redacted], [rule]),
            PicketGitLabCodeQualityReportWriter.Write([redacted]),
            PicketSarifReportWriter.Write([redacted], [rule]),
            PicketToonReportWriter.Write([redacted], [rule]),
        ];

        foreach (string report in reports)
        {
            Assert.DoesNotContain(secret, report);
            Assert.DoesNotContain(encodedSecret, report);
            Assert.DoesNotContain(CreateSha256(secret), report);
        }
    }

    private static Finding CreateFinding(
        string match,
        string secret,
        string line = "",
        IReadOnlyList<string>? decodePath = null)
    {
        return new Finding(
            "rule",
            "description",
            1,
            1,
            1,
            match.Length,
            match,
            secret,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:rule:1",
            line,
            link: "https://github.com/example/repo/blob/commit/secret.txt#L1",
            decodePath: decodePath);
    }

    private static string CreateSha256(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash);
    }
}
