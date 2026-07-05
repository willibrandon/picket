using Picket.Rules;

namespace Picket.Engine;

internal static class AwsCredentialPairMatcher
{
    private const int AccessKeyIdLength = 20;
    private const int MaxLabelPrefixLength = 128;
    private const int MaxPairWindowLength = 1024;
    private const int SecretAccessKeyLength = 40;
    private const string Pattern = """(?i)(?:aws[_ -]?access[_ -]?key[_ -]?id|secret[_ -]?access[_ -]?key)""";
    private const string RuleId = "picket-aws-access-key-pair";

    internal static bool CanHandle(SecretRule rule)
    {
        return rule.Id.Equals(RuleId, StringComparison.Ordinal)
            && rule.Pattern.Equals(Pattern, StringComparison.Ordinal)
            && rule.SecretGroup == 0;
    }

    internal static bool TryFind(
        ReadOnlySpan<byte> input,
        int startAt,
        out int matchStart,
        out int matchEnd,
        out int secretStart,
        out int secretEnd)
    {
        int position = startAt;
        while (TryFindAccessKeyId(input, position, out int keyStart, out int keyEnd))
        {
            int windowStart = Math.Max(0, keyStart - MaxPairWindowLength);
            int windowEnd = Math.Min(input.Length, keyEnd + MaxPairWindowLength);
            if (TryFindSecretAccessKey(input, windowStart, windowEnd, out secretStart, out secretEnd))
            {
                matchStart = Math.Min(FindLineStart(input, keyStart), FindLineStart(input, secretStart));
                matchEnd = Math.Max(FindLineEnd(input, keyEnd), FindLineEnd(input, secretEnd));
                return true;
            }

            position = keyStart + 1;
        }

        matchStart = 0;
        matchEnd = 0;
        secretStart = 0;
        secretEnd = 0;
        return false;
    }

    private static bool TryFindAccessKeyId(ReadOnlySpan<byte> input, int startAt, out int keyStart, out int keyEnd)
    {
        int lastStart = input.Length - AccessKeyIdLength;
        for (int start = startAt; start <= lastStart; start++)
        {
            if (IsAccessKeyIdAt(input, start))
            {
                keyStart = start;
                keyEnd = start + AccessKeyIdLength;
                return true;
            }
        }

        keyStart = 0;
        keyEnd = 0;
        return false;
    }

    private static bool TryFindSecretAccessKey(
        ReadOnlySpan<byte> input,
        int windowStart,
        int windowEnd,
        out int secretStart,
        out int secretEnd)
    {
        int lastStart = windowEnd - SecretAccessKeyLength;
        for (int start = windowStart; start <= lastStart; start++)
        {
            int end = start + SecretAccessKeyLength;
            if (IsSecretAccessKeyAt(input, start, windowEnd)
                && HasSecretAccessKeyLabelBefore(input, start))
            {
                secretStart = start;
                secretEnd = end;
                return true;
            }
        }

        secretStart = 0;
        secretEnd = 0;
        return false;
    }

    private static bool IsAccessKeyIdAt(ReadOnlySpan<byte> input, int start)
    {
        if (start > 0 && IsIdentifierByte(input[start - 1]))
        {
            return false;
        }

        int end = start + AccessKeyIdLength;
        if (end > input.Length || end < input.Length && IsIdentifierByte(input[end]))
        {
            return false;
        }

        if (!HasAwsAccessKeyIdPrefix(input[start..end]))
        {
            return false;
        }

        for (int index = start + 4; index < end; index++)
        {
            if (!IsAwsAccessKeyIdSuffixCharacter(input[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSecretAccessKeyAt(ReadOnlySpan<byte> input, int start, int windowEnd)
    {
        if (start > 0 && IsAwsSecretAccessKeyCharacter(input[start - 1]))
        {
            return false;
        }

        int end = start + SecretAccessKeyLength;
        if (end > windowEnd || end < input.Length && IsAwsSecretAccessKeyCharacter(input[end]))
        {
            return false;
        }

        for (int index = start; index < end; index++)
        {
            if (!IsAwsSecretAccessKeyCharacter(input[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasSecretAccessKeyLabelBefore(ReadOnlySpan<byte> input, int secretStart)
    {
        int lineStart = FindLineStart(input, secretStart);
        int contextStart = Math.Max(lineStart, secretStart - MaxLabelPrefixLength);
        ReadOnlySpan<byte> context = input[contextStart..secretStart];
        return HasRecentAssignmentDelimiter(context)
            && (ContainsNormalizedLabel(context, "awssecretaccesskey"u8)
                || ContainsNormalizedLabel(context, "secretaccesskey"u8)
                || ContainsNormalizedLabel(context, "awssecretkey"u8));
    }

    private static bool HasRecentAssignmentDelimiter(ReadOnlySpan<byte> context)
    {
        int start = Math.Max(0, context.Length - 32);
        for (int index = context.Length - 1; index >= start; index--)
        {
            if (context[index] is (byte)'=' or (byte)':')
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsNormalizedLabel(ReadOnlySpan<byte> input, ReadOnlySpan<byte> label)
    {
        for (int start = 0; start < input.Length; start++)
        {
            int inputIndex = start;
            int labelIndex = 0;
            while (inputIndex < input.Length && labelIndex < label.Length)
            {
                byte value = input[inputIndex];
                if (IsLabelSeparator(value))
                {
                    inputIndex++;
                    continue;
                }

                if (FoldAscii(value) != label[labelIndex])
                {
                    break;
                }

                inputIndex++;
                labelIndex++;
            }

            if (labelIndex == label.Length)
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasAwsAccessKeyIdPrefix(ReadOnlySpan<byte> candidate)
    {
        return candidate.StartsWith("AKIA"u8)
            || candidate.StartsWith("ASIA"u8)
            || candidate.StartsWith("ABIA"u8)
            || candidate.StartsWith("ACCA"u8)
            || (candidate.StartsWith("A3T"u8) && IsAsciiAlphaNumeric(candidate[3]));
    }

    private static int FindLineStart(ReadOnlySpan<byte> input, int offset)
    {
        int start = offset;
        while (start > 0 && input[start - 1] is not ((byte)'\n' or (byte)'\r'))
        {
            start--;
        }

        return start;
    }

    private static int FindLineEnd(ReadOnlySpan<byte> input, int offset)
    {
        int end = offset;
        while (end < input.Length && input[end] is not ((byte)'\n' or (byte)'\r'))
        {
            end++;
        }

        return end;
    }

    private static bool IsLabelSeparator(byte value)
    {
        return value is (byte)'_' or (byte)'-' or (byte)' ' or (byte)'\t' or (byte)'.' or (byte)'"' or (byte)'\'';
    }

    private static bool IsAwsAccessKeyIdSuffixCharacter(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'2' and <= (byte)'7';
    }

    private static bool IsAwsSecretAccessKeyCharacter(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9'
            or (byte)'+'
            or (byte)'/';
    }

    private static bool IsAsciiAlphaNumeric(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9';
    }

    private static bool IsIdentifierByte(byte value)
    {
        return IsAsciiAlphaNumeric(value) || value == (byte)'_';
    }

    private static byte FoldAscii(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            ? (byte)(value + 0x20)
            : value;
    }
}
