using Picket.Rules;
using System.Text;

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
    IReadOnlyList<SecretRequiredRule> requiredRules,
    string severity = "",
    string confidence = "",
    string rulePack = "",
    string provider = "",
    string documentationUrl = "",
    IReadOnlyList<string>? validation = null,
    IReadOnlyList<string>? revocation = null,
    bool deprecated = false,
    IReadOnlyList<string>? examples = null,
    IReadOnlyList<string>? negativeExamples = null,
    double randomnessThreshold = 0,
    bool randomnessThresholdSet = false,
    string detector = "",
    bool detectorSet = false)
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

    internal string Severity { get; } = severity ?? string.Empty;

    internal string Confidence { get; } = confidence ?? string.Empty;

    internal string RulePack { get; } = rulePack ?? string.Empty;

    internal string Provider { get; } = provider ?? string.Empty;

    internal string DocumentationUrl { get; } = documentationUrl ?? string.Empty;

    internal IReadOnlyList<string> Validation { get; } = validation ?? [];

    internal IReadOnlyList<string> Revocation { get; } = revocation ?? [];

    internal bool Deprecated { get; } = deprecated;

    internal IReadOnlyList<string> Examples { get; } = examples ?? [];

    internal IReadOnlyList<string> NegativeExamples { get; } = negativeExamples ?? [];

    internal double RandomnessThreshold { get; } = randomnessThreshold;

    internal bool RandomnessThresholdSet { get; } = randomnessThresholdSet;

    internal string Detector { get; } = detector ?? string.Empty;

    internal bool DetectorSet { get; } = detectorSet;

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
            rule.RequiredRules,
            rule.Severity,
            rule.Confidence,
            rule.RulePack,
            rule.Provider,
            rule.DocumentationUrl,
            rule.Validation,
            rule.Revocation,
            rule.Deprecated,
            rule.Examples,
            rule.NegativeExamples,
            rule.RandomnessThreshold,
            randomnessThresholdSet: true,
            detector: rule.Detector,
            detectorSet: true);
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
            baseRule.SkipReport,
            baseRule.RequiredRules,
            Severity.Length != 0 ? Severity : baseRule.Severity,
            Confidence.Length != 0 ? Confidence : baseRule.Confidence,
            RulePack.Length != 0 ? RulePack : baseRule.RulePack,
            Provider.Length != 0 ? Provider : baseRule.Provider,
            DocumentationUrl.Length != 0 ? DocumentationUrl : baseRule.DocumentationUrl,
            Validation.Count != 0 ? Validation : baseRule.Validation,
            Revocation.Count != 0 ? Revocation : baseRule.Revocation,
            Deprecated || baseRule.Deprecated,
            Examples.Count != 0 ? Examples : baseRule.Examples,
            NegativeExamples.Count != 0 ? NegativeExamples : baseRule.NegativeExamples,
            RandomnessThresholdSet ? RandomnessThreshold : baseRule.RandomnessThreshold,
            randomnessThresholdSet: true,
            detector: DetectorSet ? Detector : baseRule.Detector,
            detectorSet: true);
    }

    internal SecretRule ToRule(string sourceName)
    {
        if (string.IsNullOrWhiteSpace(Id))
        {
            throw new InvalidDataException($"{sourceName}: {CreateMissingIdMessage(Description, Pattern, PathPattern)}");
        }

        if (Pattern.Length == 0 && PathPattern.Length == 0)
        {
            throw new InvalidDataException($"{sourceName}: {Id}: both |regex| and |path| are empty, this rule will have no effect");
        }

        if (Pattern.Length != 0)
        {
            int captureGroupCount = CountCaptureGroups(Pattern);
            if (SecretGroup > captureGroupCount)
            {
                throw new InvalidDataException($"{sourceName}: {Id}: invalid regex secret group {SecretGroup}, max regex secret group {captureGroupCount}");
            }
        }

        if (Detector.Length != 0 && !PicketBuiltInDetectorNames.IsKnown(Detector))
        {
            throw new InvalidDataException($"{sourceName}: {Id}: unknown built-in detector '{Detector}'");
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
            requiredRules: RequiredRules,
            severity: Severity,
            confidence: Confidence,
            rulePack: RulePack,
            provider: Provider,
            documentationUrl: DocumentationUrl,
            validation: Validation,
            revocation: Revocation,
            deprecated: Deprecated,
            examples: Examples,
            negativeExamples: NegativeExamples,
            randomnessThreshold: RandomnessThreshold,
            detector: Detector);
    }

    internal static string CreateMissingIdMessage(string description, string pattern, string pathPattern)
    {
        var builder = new StringBuilder("rule |id| is missing or empty");
        if (!string.IsNullOrEmpty(description))
        {
            builder.Append(", description: ");
            builder.Append(description);
        }

        if (!string.IsNullOrEmpty(pattern))
        {
            builder.Append(", regex: ");
            builder.Append(pattern);
        }

        if (!string.IsNullOrEmpty(pathPattern))
        {
            builder.Append(", path: ");
            builder.Append(pathPattern);
        }

        return builder.ToString();
    }

    private static int CountCaptureGroups(string pattern)
    {
        int count = 0;
        bool escaped = false;
        bool inCharacterClass = false;
        for (int i = 0; i < pattern.Length; i++)
        {
            char c = pattern[i];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (c == '\\')
            {
                escaped = true;
                continue;
            }

            if (inCharacterClass)
            {
                if (c == ']')
                {
                    inCharacterClass = false;
                }

                continue;
            }

            if (c == '[')
            {
                inCharacterClass = true;
                continue;
            }

            if (c != '(')
            {
                continue;
            }

            if (i + 1 >= pattern.Length || pattern[i + 1] != '?')
            {
                count++;
                continue;
            }

            if (IsNamedCapture(pattern, i + 2))
            {
                count++;
            }
        }

        return count;
    }

    private static bool IsNamedCapture(string pattern, int index)
    {
        if (index + 2 < pattern.Length
            && pattern[index] == 'P'
            && pattern[index + 1] == '<')
        {
            return true;
        }

        return index + 1 < pattern.Length
            && pattern[index] == '<'
            && pattern[index + 1] is not ('=' or '!');
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
            RequiredRules,
            Severity,
            Confidence,
            RulePack,
            Provider,
            DocumentationUrl,
            Validation,
            Revocation,
            Deprecated,
            Examples,
            NegativeExamples,
            RandomnessThreshold,
            RandomnessThresholdSet,
            Detector,
            DetectorSet);
    }
}
