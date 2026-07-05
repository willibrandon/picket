namespace Picket.Rules;

/// <summary>
/// Small bootstrap subset of the pinned Gitleaks ruleset.
/// </summary>
public static class EmbeddedGitleaksRules
{
    /// <summary>
    /// Gets the bootstrap compatibility rule set used until the full pinned Gitleaks config loader lands.
    /// </summary>
    public static RuleSet Bootstrap { get; } = new(
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
