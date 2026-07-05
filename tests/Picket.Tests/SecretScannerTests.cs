using System.Text;
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

        IReadOnlyList<Finding> findings = new SecretScanner().Scan(
            new ScanRequest(input, "stdin", EmbeddedGitleaksRules.Bootstrap));

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

        IReadOnlyList<Finding> findings = new SecretScanner().Scan(
            new ScanRequest(input, "stdin", EmbeddedGitleaksRules.Bootstrap));

        Assert.IsEmpty(findings);
    }
}
