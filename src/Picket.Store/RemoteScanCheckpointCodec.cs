using Picket.Engine;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Picket.Store;

internal static class RemoteScanCheckpointCodec
{
    private const int FindingFieldCount = 44;
    private const int MetadataLineCount = 6;
    private const int PositionKindIndex = 44;
    private const int RandomnessStartIndex = 26;
    private const string BlobHeader = "blob";
    private const string FindingCountHeader = "findingCount";
    private const string OrdinalHeader = "ordinal";
    private const string PathHeader = "path";
    private const string PreviousHeader = "previous";
    private const string SymlinkHeader = "symlink";

    internal static string WriteHeader(RemoteScanCheckpointKey key)
    {
        return string.Concat("key\t", key.Fingerprint, "\n");
    }

    internal static bool TryReadHeader(string value, out string fingerprint)
    {
        fingerprint = string.Empty;
        string[] lines = value.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 1)
        {
            return false;
        }

        string[] fields = lines[0].Split('\t');
        if (fields.Length != 2 || !fields[0].Equals("key", StringComparison.Ordinal))
        {
            return false;
        }

        fingerprint = fields[1];
        return true;
    }

    internal static string WriteRecord(
        int ordinal,
        string displayPath,
        string symlinkDisplayPath,
        string blobSha256,
        string previousRecordSha256,
        IReadOnlyList<Finding> findings)
    {
        var builder = new StringBuilder();
        AppendMetadata(builder, OrdinalHeader, ordinal.ToString(CultureInfo.InvariantCulture));
        AppendMetadata(builder, PathHeader, TextFieldCodec.Encode(displayPath));
        AppendMetadata(builder, SymlinkHeader, TextFieldCodec.Encode(symlinkDisplayPath));
        AppendMetadata(builder, BlobHeader, blobSha256);
        AppendMetadata(builder, PreviousHeader, previousRecordSha256);
        AppendMetadata(builder, FindingCountHeader, findings.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < findings.Count; i++)
        {
            WriteFinding(builder, findings[i]);
        }

        return builder.ToString();
    }

    internal static bool TryReadRecord(
        string value,
        string expectedPreviousRecordSha256,
        [NotNullWhen(true)] out RemoteScanCheckpointEntry? entry)
    {
        entry = null;
        string[] lines = value.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < MetadataLineCount
            || !TryReadMetadata(lines[0], OrdinalHeader, out string ordinalText)
            || !int.TryParse(ordinalText, CultureInfo.InvariantCulture, out int ordinal)
            || ordinal < 0
            || !TryReadMetadata(lines[1], PathHeader, out string encodedPath)
            || !TryReadMetadata(lines[2], SymlinkHeader, out string encodedSymlink)
            || !TryReadMetadata(lines[3], BlobHeader, out string blobSha256)
            || !TryReadMetadata(lines[4], PreviousHeader, out string previousRecordSha256)
            || !previousRecordSha256.Equals(expectedPreviousRecordSha256, StringComparison.Ordinal)
            || !TryReadMetadata(lines[5], FindingCountHeader, out string findingCountText)
            || !int.TryParse(findingCountText, CultureInfo.InvariantCulture, out int findingCount)
            || findingCount < 0
            || lines.Length != MetadataLineCount + findingCount)
        {
            return false;
        }

        try
        {
            string displayPath = TextFieldCodec.Decode(encodedPath);
            string symlinkDisplayPath = TextFieldCodec.Decode(encodedSymlink);
            var findings = new List<Finding>(findingCount);
            for (int i = 0; i < findingCount; i++)
            {
                if (!TryReadFinding(lines[MetadataLineCount + i], out Finding? finding))
                {
                    return false;
                }

                findings.Add(finding);
            }

            entry = new RemoteScanCheckpointEntry(ordinal, displayPath, symlinkDisplayPath, blobSha256, string.Empty, findings);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            entry = null;
            return false;
        }
    }

    private static void WriteFinding(StringBuilder builder, Finding finding)
    {
        builder.Append("finding");
        AppendField(builder, TextFieldCodec.Encode(finding.RuleID));
        AppendField(builder, TextFieldCodec.Encode(finding.Description));
        AppendField(builder, finding.StartLine.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, finding.EndLine.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, finding.StartColumn.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, finding.EndColumn.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, TextFieldCodec.Encode(finding.Match));
        AppendField(builder, TextFieldCodec.Encode(finding.Secret));
        AppendField(builder, TextFieldCodec.Encode(finding.File));
        AppendField(builder, TextFieldCodec.Encode(finding.SymlinkFile));
        AppendField(builder, TextFieldCodec.Encode(finding.Commit));
        AppendField(builder, finding.Entropy.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, TextFieldCodec.Encode(finding.Author));
        AppendField(builder, TextFieldCodec.Encode(finding.Email));
        AppendField(builder, TextFieldCodec.Encode(finding.Date));
        AppendField(builder, TextFieldCodec.Encode(finding.Message));
        AppendField(builder, TextFieldCodec.EncodeTags(finding.Tags));
        AppendField(builder, TextFieldCodec.Encode(finding.Fingerprint));
        AppendField(builder, TextFieldCodec.Encode(finding.Line));
        AppendField(builder, TextFieldCodec.Encode(finding.Link));
        AppendField(builder, TextFieldCodec.Encode(finding.SecretSha256));
        AppendField(builder, TextFieldCodec.Encode(finding.MatchSha256));
        AppendField(builder, TextFieldCodec.Encode(finding.ValidationState));
        AppendField(builder, TextFieldCodec.Encode(finding.BlobSha256));
        AppendField(builder, TextFieldCodec.EncodeTags(finding.DecodePath));
        AppendRandomness(builder, finding.Randomness);
        AppendField(builder, finding.PositionKind.ToString());
        builder.Append('\n');
    }

    private static bool TryReadFinding(string line, [NotNullWhen(true)] out Finding? finding)
    {
        finding = null;
        string[] fields = line.Split('\t');
        if (fields.Length != FindingFieldCount + 1
            || !fields[0].Equals("finding", StringComparison.Ordinal)
            || !int.TryParse(fields[3], CultureInfo.InvariantCulture, out int startLine)
            || !int.TryParse(fields[4], CultureInfo.InvariantCulture, out int endLine)
            || !int.TryParse(fields[5], CultureInfo.InvariantCulture, out int startColumn)
            || !int.TryParse(fields[6], CultureInfo.InvariantCulture, out int endColumn)
            || !double.TryParse(fields[12], CultureInfo.InvariantCulture, out double entropy)
            || !TryParseRandomness(fields.AsSpan(RandomnessStartIndex, PositionKindIndex - RandomnessStartIndex), out SecretRandomnessAssessment? randomness)
            || !Enum.TryParse(fields[PositionKindIndex], ignoreCase: false, out FindingPositionKind positionKind)
            || !Enum.IsDefined(positionKind))
        {
            return false;
        }

        finding = new Finding(
            TextFieldCodec.Decode(fields[1]),
            TextFieldCodec.Decode(fields[2]),
            startLine,
            endLine,
            startColumn,
            endColumn,
            TextFieldCodec.Decode(fields[7]),
            TextFieldCodec.Decode(fields[8]),
            TextFieldCodec.Decode(fields[9]),
            TextFieldCodec.Decode(fields[10]),
            TextFieldCodec.Decode(fields[11]),
            entropy,
            TextFieldCodec.Decode(fields[13]),
            TextFieldCodec.Decode(fields[14]),
            TextFieldCodec.Decode(fields[15]),
            TextFieldCodec.Decode(fields[16]),
            TextFieldCodec.DecodeTags(fields[17]),
            TextFieldCodec.Decode(fields[18]),
            TextFieldCodec.Decode(fields[19]),
            TextFieldCodec.Decode(fields[20]),
            TextFieldCodec.Decode(fields[21]),
            TextFieldCodec.Decode(fields[22]),
            TextFieldCodec.Decode(fields[23]),
            TextFieldCodec.Decode(fields[24]),
            TextFieldCodec.DecodeTags(fields[25]),
            randomness,
            positionKind: positionKind);
        return true;
    }

    private static void AppendRandomness(StringBuilder builder, SecretRandomnessAssessment? assessment)
    {
        if (assessment is null)
        {
            for (int i = RandomnessStartIndex; i < PositionKindIndex; i++)
            {
                AppendField(builder, string.Empty);
            }

            return;
        }

        SecretRandomnessFeatures features = assessment.Features;
        AppendField(builder, TextFieldCodec.Encode(assessment.Model));
        AppendField(builder, assessment.Score.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, TextFieldCodec.Encode(assessment.Classification));
        AppendField(builder, features.SampleOffset.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, features.SampleLength.ToString(CultureInfo.InvariantCulture));
        AppendField(builder, TextFieldCodec.Encode(features.Alphabet));
        AppendField(builder, features.LengthScore.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.NormalizedEntropy.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.ExpectedDistinctRatio.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.TransitionDiversity.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.LongestRunRatio.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.SequentialPairRatio.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.RepeatedPatternRatio.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.CommonBigramRatio.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.CharacterClassBalance.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.EncodedTextSignal.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, features.PlaceholderSignal.ToString("G17", CultureInfo.InvariantCulture));
        AppendField(builder, TextFieldCodec.EncodeTags(assessment.Signals));
    }

    private static bool TryParseRandomness(
        ReadOnlySpan<string> fields,
        out SecretRandomnessAssessment? assessment)
    {
        assessment = null;
        if (fields.Length != PositionKindIndex - RandomnessStartIndex)
        {
            return false;
        }

        if (fields[0].Length == 0)
        {
            for (int i = 1; i < fields.Length; i++)
            {
                if (fields[i].Length != 0)
                {
                    return false;
                }
            }

            return true;
        }

        if (!double.TryParse(fields[1], CultureInfo.InvariantCulture, out double score)
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

    private static void AppendMetadata(StringBuilder builder, string name, string value)
    {
        builder.Append(name);
        builder.Append('\t');
        builder.Append(value);
        builder.Append('\n');
    }

    private static void AppendField(StringBuilder builder, string value)
    {
        builder.Append('\t');
        builder.Append(value);
    }

    private static bool TryReadMetadata(string line, string expectedName, out string value)
    {
        value = string.Empty;
        int separator = line.IndexOf('\t');
        if (separator <= 0 || !line.AsSpan(0, separator).SequenceEqual(expectedName))
        {
            return false;
        }

        value = line[(separator + 1)..];
        return true;
    }
}
