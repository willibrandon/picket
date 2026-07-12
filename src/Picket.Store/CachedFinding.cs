using Picket.Engine;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Picket.Store;

internal sealed class CachedFinding(
    string ruleId,
    string description,
    int startLine,
    int endLine,
    int startColumn,
    int endColumn,
    string match,
    string secret,
    string line,
    double entropy,
    IReadOnlyList<string> tags,
    string secretSha256,
    string matchSha256,
    string validationState,
    IReadOnlyList<string> decodePath,
    SecretRandomnessAssessment? randomness,
    bool protectRandomness)
{
    private const int CurrentFieldCount = 33;

    internal static CachedFinding FromFinding(
        Finding finding,
        ScanCacheStorageMode storageMode,
        ReadOnlySpan<byte> fieldProtectionKey)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (storageMode == ScanCacheStorageMode.SecretHashOnly)
        {
            string secretSha256 = CreateSecretSha256(finding);
            string matchSha256 = CreateMatchSha256(finding);
            return new CachedFinding(
                finding.RuleID,
                finding.Description,
                finding.StartLine,
                finding.EndLine,
                finding.StartColumn,
                finding.EndColumn,
                string.Empty,
                string.Empty,
                string.Empty,
                finding.Entropy,
                finding.Tags,
                ProtectedCacheField.Protect(fieldProtectionKey, secretSha256),
                ProtectedCacheField.Protect(fieldProtectionKey, matchSha256),
                finding.ValidationState,
                finding.DecodePath,
                finding.Randomness,
                protectRandomness: true);
        }

        return new CachedFinding(
            finding.RuleID,
            finding.Description,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            finding.Line,
            finding.Entropy,
            finding.Tags,
            finding.SecretSha256,
            finding.MatchSha256,
            finding.ValidationState,
            finding.DecodePath,
            finding.Randomness,
            protectRandomness: false);
    }

    internal static bool TryParse(
        ReadOnlySpan<string> fields,
        ScanCacheStorageMode storageMode,
        ReadOnlySpan<byte> fieldProtectionKey,
        [NotNullWhen(true)] out CachedFinding? finding)
    {
        finding = null;
        if (fields.Length != CurrentFieldCount)
        {
            return false;
        }

        if (!int.TryParse(fields[2], CultureInfo.InvariantCulture, out int startLine)
            || !int.TryParse(fields[3], CultureInfo.InvariantCulture, out int endLine)
            || !int.TryParse(fields[4], CultureInfo.InvariantCulture, out int startColumn)
            || !int.TryParse(fields[5], CultureInfo.InvariantCulture, out int endColumn)
            || !double.TryParse(fields[9], CultureInfo.InvariantCulture, out double entropy))
        {
            return false;
        }

        try
        {
            string secretSha256 = TextFieldCodec.Decode(fields[11]);
            string matchSha256 = TextFieldCodec.Decode(fields[12]);
            if (storageMode == ScanCacheStorageMode.SecretHashOnly
                && (!ProtectedCacheField.TryUnprotect(fieldProtectionKey, secretSha256, out secretSha256)
                    || !ProtectedCacheField.TryUnprotect(fieldProtectionKey, matchSha256, out matchSha256)))
            {
                return false;
            }

            if (!TryParseRandomness(fields, storageMode, fieldProtectionKey, out SecretRandomnessAssessment? randomness))
            {
                return false;
            }

            finding = new CachedFinding(
                TextFieldCodec.Decode(fields[0]),
                TextFieldCodec.Decode(fields[1]),
                startLine,
                endLine,
                startColumn,
                endColumn,
                TextFieldCodec.Decode(fields[6]),
                TextFieldCodec.Decode(fields[7]),
                TextFieldCodec.Decode(fields[8]),
                entropy,
                TextFieldCodec.DecodeTags(fields[10]),
                secretSha256,
                matchSha256,
                TextFieldCodec.Decode(fields[13]),
                TextFieldCodec.DecodeTags(fields[14]),
                randomness,
                storageMode == ScanCacheStorageMode.SecretHashOnly);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            finding = null;
            return false;
        }
    }

    internal void Write(StringBuilder builder, ReadOnlySpan<byte> fieldProtectionKey)
    {
        builder.Append("finding");
        Append(builder, TextFieldCodec.Encode(ruleId));
        Append(builder, TextFieldCodec.Encode(description));
        Append(builder, startLine.ToString(CultureInfo.InvariantCulture));
        Append(builder, endLine.ToString(CultureInfo.InvariantCulture));
        Append(builder, startColumn.ToString(CultureInfo.InvariantCulture));
        Append(builder, endColumn.ToString(CultureInfo.InvariantCulture));
        Append(builder, TextFieldCodec.Encode(match));
        Append(builder, TextFieldCodec.Encode(secret));
        Append(builder, TextFieldCodec.Encode(line));
        Append(builder, entropy.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, TextFieldCodec.EncodeTags(tags));
        Append(builder, TextFieldCodec.Encode(secretSha256));
        Append(builder, TextFieldCodec.Encode(matchSha256));
        Append(builder, TextFieldCodec.Encode(validationState));
        Append(builder, TextFieldCodec.EncodeTags(decodePath));
        if (protectRandomness)
        {
            AppendProtectedRandomness(builder, randomness, fieldProtectionKey);
        }
        else
        {
            AppendRandomness(builder, randomness);
        }

        builder.Append('\n');
    }

    internal Finding ToFinding(string fileName, string symlinkFile, string blobSha256)
    {
        return new Finding(
            ruleId,
            description,
            startLine,
            endLine,
            startColumn,
            endColumn,
            match,
            secret,
            fileName,
            symlinkFile,
            string.Empty,
            entropy,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            tags,
            CreateFingerprint(fileName, ruleId, startLine),
            line,
            string.Empty,
            secretSha256,
            matchSha256,
            validationState,
            blobSha256,
            decodePath,
            randomness);
    }

    private static void AppendRandomness(StringBuilder builder, SecretRandomnessAssessment? assessment)
    {
        if (assessment is null)
        {
            for (int i = 15; i < CurrentFieldCount; i++)
            {
                Append(builder, string.Empty);
            }

            return;
        }

        SecretRandomnessFeatures features = assessment.Features;
        Append(builder, TextFieldCodec.Encode(assessment.Model));
        Append(builder, assessment.Score.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, TextFieldCodec.Encode(assessment.Classification));
        Append(builder, features.SampleOffset.ToString(CultureInfo.InvariantCulture));
        Append(builder, features.SampleLength.ToString(CultureInfo.InvariantCulture));
        Append(builder, TextFieldCodec.Encode(features.Alphabet));
        Append(builder, features.LengthScore.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.NormalizedEntropy.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.ExpectedDistinctRatio.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.TransitionDiversity.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.LongestRunRatio.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.SequentialPairRatio.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.RepeatedPatternRatio.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.CommonBigramRatio.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.CharacterClassBalance.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.EncodedTextSignal.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, features.PlaceholderSignal.ToString("G17", CultureInfo.InvariantCulture));
        Append(builder, TextFieldCodec.EncodeTags(assessment.Signals));
    }

    private static void AppendProtectedRandomness(
        StringBuilder builder,
        SecretRandomnessAssessment? assessment,
        ReadOnlySpan<byte> fieldProtectionKey)
    {
        if (assessment is null)
        {
            AppendRandomness(builder, assessment);
            return;
        }

        var payloadBuilder = new StringBuilder();
        AppendRandomness(payloadBuilder, assessment);
        string payload = payloadBuilder.ToString(1, payloadBuilder.Length - 1);
        Append(builder, TextFieldCodec.Encode(ProtectedCacheField.Protect(fieldProtectionKey, payload)));
        for (int i = 16; i < CurrentFieldCount; i++)
        {
            Append(builder, string.Empty);
        }
    }

    private static bool TryParseRandomness(
        ReadOnlySpan<string> fields,
        ScanCacheStorageMode storageMode,
        ReadOnlySpan<byte> fieldProtectionKey,
        out SecretRandomnessAssessment? assessment)
    {
        assessment = null;
        if (fields[15].Length == 0)
        {
            for (int i = 16; i < CurrentFieldCount; i++)
            {
                if (fields[i].Length != 0)
                {
                    return false;
                }
            }

            return true;
        }

        if (storageMode == ScanCacheStorageMode.SecretHashOnly)
        {
            for (int i = 16; i < CurrentFieldCount; i++)
            {
                if (fields[i].Length != 0)
                {
                    assessment = null;
                    return false;
                }
            }

            string protectedPayload = TextFieldCodec.Decode(fields[15]);
            if (!ProtectedCacheField.TryUnprotect(fieldProtectionKey, protectedPayload, out string payload))
            {
                assessment = null;
                return false;
            }

            string[] protectedFields = payload.Split('\t');
            return TryParseRandomnessFields(protectedFields, out assessment);
        }

        return TryParseRandomnessFields(fields[15..], out assessment);
    }

    private static bool TryParseRandomnessFields(
        ReadOnlySpan<string> fields,
        out SecretRandomnessAssessment? assessment)
    {
        assessment = null;
        if (fields.Length != CurrentFieldCount - 15
            || !double.TryParse(fields[1], CultureInfo.InvariantCulture, out double score)
            || !int.TryParse(fields[3], CultureInfo.InvariantCulture, out int sampleOffset)
            || !int.TryParse(fields[4], CultureInfo.InvariantCulture, out int sampleLength)
            || !double.TryParse(fields[6], CultureInfo.InvariantCulture, out double lengthScore)
            || !double.TryParse(fields[7], CultureInfo.InvariantCulture, out double normalizedEntropy)
            || !double.TryParse(fields[8], CultureInfo.InvariantCulture, out double expectedDistinctRatio)
            || !double.TryParse(fields[9], CultureInfo.InvariantCulture, out double transitionDiversity)
            || !double.TryParse(fields[10], CultureInfo.InvariantCulture, out double longestRunRatio)
            || !double.TryParse(fields[11], CultureInfo.InvariantCulture, out double sequentialPairRatio)
            || !double.TryParse(fields[12], CultureInfo.InvariantCulture, out double repeatedPatternRatio)
            || !double.TryParse(fields[13], CultureInfo.InvariantCulture, out double commonBigramRatio)
            || !double.TryParse(fields[14], CultureInfo.InvariantCulture, out double characterClassBalance)
            || !double.TryParse(fields[15], CultureInfo.InvariantCulture, out double encodedTextSignal)
            || !double.TryParse(fields[16], CultureInfo.InvariantCulture, out double placeholderSignal))
        {
            return false;
        }

        SecretRandomnessFeatures features = SecretRandomnessFeatures.Create(
            sampleOffset,
            sampleLength,
            TextFieldCodec.Decode(fields[5]),
            lengthScore,
            normalizedEntropy,
            expectedDistinctRatio,
            transitionDiversity,
            longestRunRatio,
            sequentialPairRatio,
            repeatedPatternRatio,
            commonBigramRatio,
            characterClassBalance,
            encodedTextSignal,
            placeholderSignal);
        assessment = SecretRandomnessAssessment.Create(
            TextFieldCodec.Decode(fields[0]),
            score,
            TextFieldCodec.Decode(fields[2]),
            features,
            TextFieldCodec.DecodeTags(fields[17]));
        return true;
    }

    private static void Append(StringBuilder builder, string value)
    {
        builder.Append('\t');
        builder.Append(value);
    }

    private static string CreateFingerprint(string fileName, string ruleId, int startLine)
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{fileName}:{ruleId}:{startLine}");
    }

    private static string CreateSecretSha256(Finding finding)
    {
        return finding.SecretSha256.Length == 0 ? BlobHasher.ComputeSha256Hex(finding.Secret) : finding.SecretSha256;
    }

    private static string CreateMatchSha256(Finding finding)
    {
        return finding.MatchSha256.Length == 0 ? BlobHasher.ComputeSha256Hex(finding.Match) : finding.MatchSha256;
    }
}
