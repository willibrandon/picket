using Picket.Engine;
using Picket.Report;

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

    private static Finding CreateFinding(string match, string secret)
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
            "secret.txt:rule:1");
    }
}
