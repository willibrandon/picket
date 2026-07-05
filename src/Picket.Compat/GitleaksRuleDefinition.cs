using Picket.Rules;

namespace Picket.Compat;

internal sealed class GitleaksRuleDefinition(
    string id,
    string description,
    string pattern,
    int secretGroup,
    double entropy,
    string pathPattern,
    IReadOnlyList<SecretAllowlist> allowlists,
    IReadOnlyList<string> keywords,
    IReadOnlyList<string> tags,
    bool skipReport,
    IReadOnlyList<SecretRequiredRule> requiredRules)
{
    internal string Id { get; } = id ?? string.Empty;

    internal string Description { get; } = description ?? string.Empty;

    internal string Pattern { get; } = pattern ?? string.Empty;

    internal int SecretGroup { get; } = secretGroup;

    internal double Entropy { get; } = entropy;

    internal string PathPattern { get; } = pathPattern ?? string.Empty;

    internal IReadOnlyList<SecretAllowlist> Allowlists { get; } = allowlists ?? [];

    internal IReadOnlyList<string> Keywords { get; } = keywords ?? [];

    internal IReadOnlyList<string> Tags { get; } = tags ?? [];

    internal bool SkipReport { get; } = skipReport;

    internal IReadOnlyList<SecretRequiredRule> RequiredRules { get; } = requiredRules ?? [];

    internal static GitleaksRuleDefinition FromRule(SecretRule rule)
    {
        return new GitleaksRuleDefinition(
            rule.Id,
            rule.Description,
            rule.Pattern,
            rule.SecretGroup,
            rule.Entropy,
            rule.PathPattern,
            rule.Allowlists,
            rule.Keywords,
            rule.Tags,
            rule.SkipReport,
            rule.RequiredRules);
    }

    internal GitleaksRuleDefinition MergeWithBase(SecretRule baseRule)
    {
        return new GitleaksRuleDefinition(
            baseRule.Id,
            Description.Length != 0 ? Description : baseRule.Description,
            Pattern.Length != 0 ? Pattern : baseRule.Pattern,
            SecretGroup != 0 ? SecretGroup : baseRule.SecretGroup,
            Entropy != 0 ? Entropy : baseRule.Entropy,
            PathPattern.Length != 0 ? PathPattern : baseRule.PathPattern,
            [.. baseRule.Allowlists, .. Allowlists],
            [.. baseRule.Keywords, .. Keywords],
            [.. baseRule.Tags, .. Tags],
            SkipReport || baseRule.SkipReport,
            RequiredRules.Count != 0 ? RequiredRules : baseRule.RequiredRules);
    }

    internal SecretRule ToRule(string sourceName)
    {
        if (string.IsNullOrWhiteSpace(Id))
        {
            throw new InvalidDataException($"{sourceName}: rule |id| is missing or empty");
        }

        if (Pattern.Length == 0 && PathPattern.Length == 0)
        {
            throw new InvalidDataException($"{sourceName}: {Id}: both |regex| and |path| are empty");
        }

        return SecretRule.Create(
            Id,
            Description,
            Pattern,
            secretGroup: SecretGroup,
            entropy: Entropy,
            pathPattern: PathPattern,
            allowlists: Allowlists,
            keywords: Keywords,
            tags: Tags,
            skipReport: SkipReport,
            requiredRules: RequiredRules);
    }

    internal GitleaksRuleDefinition WithAdditionalAllowlists(IReadOnlyList<SecretAllowlist> allowlists)
    {
        return new GitleaksRuleDefinition(
            Id,
            Description,
            Pattern,
            SecretGroup,
            Entropy,
            PathPattern,
            [.. Allowlists, .. allowlists],
            Keywords,
            Tags,
            SkipReport,
            RequiredRules);
    }
}
