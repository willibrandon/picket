using Picket.Rules;

namespace Picket.Tests;

/// <summary>
/// Provides focused rule sets for scanner integration tests.
/// </summary>
internal static class TestRuleSets
{
    /// <summary>
    /// Gets a rule set that detects AWS access-key identifiers.
    /// </summary>
    internal static RuleSet AwsAccessToken { get; } = new(
    [
        SecretRule.Create(
            "aws-access-token",
            "AWS Access Token",
            @"\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\b",
            secretGroup: 1,
            keywords: ["AKIA", "ASIA"],
            tags: ["key", "AWS"])
    ]);
}
