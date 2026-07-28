using Picket.Rules;

namespace Picket.Engine;

internal readonly struct NativePredicateEvaluationContext(
    string sourcePath,
    string sourceSymlink,
    Finding? finding = null,
    SecretRule? rule = null)
{
    private static readonly IReadOnlyList<string> s_emptyStrings = [];

    internal NativePredicateValue GetValue(NativePredicateField field)
    {
        return field switch
        {
            NativePredicateField.SourcePath => NativePredicateValue.FromString(sourcePath),
            NativePredicateField.SourceSymlink => NativePredicateValue.FromString(sourceSymlink),
            NativePredicateField.FindingRuleId => NativePredicateValue.FromString(finding?.RuleID ?? string.Empty),
            NativePredicateField.FindingDescription => NativePredicateValue.FromString(finding?.Description ?? string.Empty),
            NativePredicateField.FindingMatch => NativePredicateValue.FromString(finding?.Match ?? string.Empty),
            NativePredicateField.FindingSecret => NativePredicateValue.FromString(finding?.Secret ?? string.Empty),
            NativePredicateField.FindingLine => NativePredicateValue.FromString(finding?.Line ?? string.Empty),
            NativePredicateField.FindingStartLine => NativePredicateValue.FromNumber(finding?.StartLine ?? 0),
            NativePredicateField.FindingEndLine => NativePredicateValue.FromNumber(finding?.EndLine ?? 0),
            NativePredicateField.FindingStartColumn => NativePredicateValue.FromNumber(finding?.StartColumn ?? 0),
            NativePredicateField.FindingEndColumn => NativePredicateValue.FromNumber(finding?.EndColumn ?? 0),
            NativePredicateField.FindingEntropy => NativePredicateValue.FromNumber(finding?.Entropy ?? 0),
            NativePredicateField.FindingRandomnessScore => NativePredicateValue.FromNumber(finding?.Randomness?.Score ?? 0),
            NativePredicateField.FindingDecodeDepth => NativePredicateValue.FromNumber(finding?.DecodePath.Count ?? 0),
            NativePredicateField.FindingIsDecoded => NativePredicateValue.FromBoolean(finding?.DecodePath.Count > 0),
            NativePredicateField.FindingTags => NativePredicateValue.FromStringList(finding?.Tags ?? s_emptyStrings),
            NativePredicateField.FindingDecodePath => NativePredicateValue.FromStringList(finding?.DecodePath ?? s_emptyStrings),
            NativePredicateField.FindingSeverity => NativePredicateValue.FromString(rule?.Severity ?? string.Empty),
            NativePredicateField.FindingConfidence => NativePredicateValue.FromString(rule?.Confidence ?? string.Empty),
            NativePredicateField.FindingRulePack => NativePredicateValue.FromString(rule?.RulePack ?? string.Empty),
            NativePredicateField.FindingProvider => NativePredicateValue.FromString(rule?.Provider ?? string.Empty),
            _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown native predicate field."),
        };
    }

    internal NativePredicateEvaluationContext WithFinding(Finding value, SecretRule owner)
    {
        return new NativePredicateEvaluationContext(sourcePath, sourceSymlink, value, owner);
    }
}
