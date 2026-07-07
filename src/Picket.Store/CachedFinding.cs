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
    IReadOnlyList<string> decodePath)
{
    private const int CurrentFieldCount = 15;
    private const int LegacyFieldCount = 14;

    internal static CachedFinding FromFinding(Finding finding, ScanCacheStorageMode storageMode)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (storageMode == ScanCacheStorageMode.SecretHashOnly)
        {
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
                CreateSecretSha256(finding),
                CreateMatchSha256(finding),
                finding.ValidationState,
                finding.DecodePath);
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
            finding.DecodePath);
    }

    internal static bool TryParse(ReadOnlySpan<string> fields, [NotNullWhen(true)] out CachedFinding? finding)
    {
        finding = null;
        if (fields.Length is not (CurrentFieldCount or LegacyFieldCount))
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
                TextFieldCodec.Decode(fields[11]),
                TextFieldCodec.Decode(fields[12]),
                TextFieldCodec.Decode(fields[13]),
                fields.Length == CurrentFieldCount ? TextFieldCodec.DecodeTags(fields[14]) : []);
            return true;
        }
        catch (FormatException)
        {
            finding = null;
            return false;
        }
    }

    internal void Write(StringBuilder builder)
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
            decodePath);
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
