using Picket.Rules;

namespace Picket.Engine;

internal static class GenericApiKeyMatcher
{
    private const string RuleId = "generic-api-key";
    private const string Pattern = """(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)""";

    internal static bool CanHandle(SecretRule rule)
    {
        return rule.Id.Equals(RuleId, StringComparison.Ordinal)
            && rule.Pattern.Equals(Pattern, StringComparison.Ordinal)
            && rule.SecretGroup is 0 or 1;
    }

    internal static bool TryFind(
        ReadOnlySpan<byte> input,
        int startAt,
        out int matchStart,
        out int matchEnd,
        out int secretStart,
        out int secretEnd)
    {
        for (int start = startAt; start < input.Length; start++)
        {
            if (TryMatchAt(input, start, out matchEnd, out secretStart, out secretEnd))
            {
                matchStart = start;
                return true;
            }
        }

        matchStart = 0;
        matchEnd = 0;
        secretStart = 0;
        secretEnd = 0;
        return false;
    }

    private static bool TryMatchAt(
        ReadOnlySpan<byte> input,
        int start,
        out int matchEnd,
        out int secretStart,
        out int secretEnd)
    {
        int maxPrefixLength = Math.Min(50, input.Length - start);
        for (int prefixLength = 0; prefixLength <= maxPrefixLength; prefixLength++)
        {
            int keywordStart = start + prefixLength;
            if (prefixLength > 0 && !IsPrefixByte(input[keywordStart - 1]))
            {
                break;
            }

            if (!TryMatchKeyword(input[keywordStart..], out int keywordLength))
            {
                continue;
            }

            int afterKeyword = keywordStart + keywordLength;
            int maxTailLength = Math.Min(20, input.Length - afterKeyword);
            for (int tailLength = maxTailLength; tailLength >= 0; tailLength--)
            {
                if (!IsTail(input.Slice(afterKeyword, tailLength)))
                {
                    continue;
                }

                int afterTail = afterKeyword + tailLength;
                int maxSeparatorLength = Math.Min(3, input.Length - afterTail);
                for (int separatorLength = maxSeparatorLength; separatorLength >= 0; separatorLength--)
                {
                    if (!IsSeparator(input.Slice(afterTail, separatorLength)))
                    {
                        continue;
                    }

                    int operatorStart = afterTail + separatorLength;
                    if (!TryMatchOperator(input[operatorStart..], out int operatorLength))
                    {
                        continue;
                    }

                    int afterOperator = operatorStart + operatorLength;
                    if (TryMatchPaddedSecret(input, afterOperator, out matchEnd, out secretStart, out secretEnd))
                    {
                        return true;
                    }
                }
            }
        }

        matchEnd = 0;
        secretStart = 0;
        secretEnd = 0;
        return false;
    }

    private static bool TryMatchPaddedSecret(
        ReadOnlySpan<byte> input,
        int start,
        out int matchEnd,
        out int secretStart,
        out int secretEnd)
    {
        int maxPaddingLength = Math.Min(5, input.Length - start);
        for (int paddingLength = maxPaddingLength; paddingLength >= 0; paddingLength--)
        {
            if (!IsSecretPadding(input.Slice(start, paddingLength)))
            {
                continue;
            }

            int candidateSecretStart = start + paddingLength;
            if (TryMatchWordSecret(input, candidateSecretStart, out int candidateSecretEnd)
                || TryMatchBase64Secret(input, candidateSecretStart, out candidateSecretEnd))
            {
                if (TryConsumeTerminator(input, candidateSecretEnd, out matchEnd))
                {
                    secretStart = candidateSecretStart;
                    secretEnd = candidateSecretEnd;
                    return true;
                }
            }
        }

        matchEnd = 0;
        secretStart = 0;
        secretEnd = 0;
        return false;
    }

    private static bool TryMatchWordSecret(ReadOnlySpan<byte> input, int start, out int end)
    {
        int position = start;
        int limit = Math.Min(input.Length, start + 150);
        while (position < limit && IsWordSecretByte(input[position]))
        {
            position++;
        }

        if (position - start >= 10)
        {
            end = position;
            return true;
        }

        end = 0;
        return false;
    }

    private static bool TryMatchBase64Secret(ReadOnlySpan<byte> input, int start, out int end)
    {
        if (start >= input.Length || !IsAsciiLowerDigit(input[start]))
        {
            end = 0;
            return false;
        }

        int position = start + 1;
        while (position < input.Length && IsLowerBase64Byte(input[position]))
        {
            position++;
        }

        int base64Length = position - start;
        int equalsLength = 0;
        while (position < input.Length && equalsLength < 3 && input[position] == (byte)'=')
        {
            position++;
            equalsLength++;
        }

        if (base64Length >= 12)
        {
            end = position;
            return true;
        }

        end = 0;
        return false;
    }

    private static bool TryConsumeTerminator(ReadOnlySpan<byte> input, int position, out int matchEnd)
    {
        if (position == input.Length)
        {
            matchEnd = position;
            return true;
        }

        byte value = input[position];
        if (value is (byte)'`' or (byte)'\'' or (byte)'"' or (byte)';' || IsWhitespace(value))
        {
            matchEnd = position + 1;
            return true;
        }

        if (position + 1 < input.Length
            && value == (byte)'\\'
            && input[position + 1] is (byte)'n' or (byte)'r')
        {
            matchEnd = position + 2;
            return true;
        }

        matchEnd = 0;
        return false;
    }

    private static bool TryMatchKeyword(ReadOnlySpan<byte> input, out int length)
    {
        ReadOnlySpan<byte> lower = "access"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "auth"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "api"u8;
        if (StartsWithApiKeyword(input))
        {
            length = lower.Length;
            return true;
        }

        lower = "credential"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "creds"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "key"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "password"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "passwd"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "secret"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        lower = "token"u8;
        if (StartsWithAsciiIgnoreCase(input, lower))
        {
            length = lower.Length;
            return true;
        }

        length = 0;
        return false;
    }

    private static bool TryMatchOperator(ReadOnlySpan<byte> input, out int length)
    {
        if (input.IsEmpty)
        {
            length = 0;
            return false;
        }

        if (input[0] is (byte)'=' or (byte)'>' or (byte)',')
        {
            length = 1;
            return true;
        }

        if (input[0] == (byte)':')
        {
            if (input.Length >= 2 && input[1] == (byte)'=')
            {
                length = 2;
                return true;
            }

            if (input.Length >= 3 && input[1] == (byte)':' && input[2] == (byte)'=')
            {
                length = 3;
                return true;
            }

            if (input.Length >= 4 && input[1] == (byte)':' && input[2] == (byte)':' && input[3] == (byte)'=')
            {
                length = 4;
                return true;
            }

            length = 1;
            return true;
        }

        if (input.Length >= 2)
        {
            if (input[0] == (byte)'|' && input[1] == (byte)'|')
            {
                length = 2;
                return true;
            }

            if (input[0] == (byte)'=' && input[1] == (byte)'>')
            {
                length = 2;
                return true;
            }

            if (input[0] == (byte)'?' && input[1] == (byte)'=')
            {
                length = 2;
                return true;
            }
        }

        length = 0;
        return false;
    }

    private static bool IsTail(ReadOnlySpan<byte> input)
    {
        foreach (byte value in input)
        {
            if (!IsTailByte(value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSeparator(ReadOnlySpan<byte> input)
    {
        foreach (byte value in input)
        {
            if (!IsWhitespace(value) && value is not ((byte)'\'' or (byte)'"'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSecretPadding(ReadOnlySpan<byte> input)
    {
        foreach (byte value in input)
        {
            if (!IsWhitespace(value) && value is not ((byte)'`' or (byte)'\'' or (byte)'"' or (byte)'='))
            {
                return false;
            }
        }

        return true;
    }

    private static bool StartsWithApiKeyword(ReadOnlySpan<byte> input)
    {
        return input.Length >= 3
            && input[1] == (byte)'p'
            && (input[0] == (byte)'A' || input[0] == (byte)'a')
            && (input[2] == (byte)'i' || input[2] == (byte)'I');
    }

    private static bool StartsWithAsciiIgnoreCase(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyword)
    {
        if (input.Length < keyword.Length)
        {
            return false;
        }

        for (int index = 0; index < keyword.Length; index++)
        {
            if (FoldAscii(input[index]) != keyword[index])
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsPrefixByte(byte value)
    {
        return IsWordByte(value) || value is (byte)'.' or (byte)'-';
    }

    private static bool IsTailByte(byte value)
    {
        return value is (byte)' ' or (byte)'\t' || IsPrefixByte(value);
    }

    private static bool IsWordSecretByte(byte value)
    {
        return IsWordByte(value) || value is (byte)'.' or (byte)'=' or (byte)'-';
    }

    private static bool IsLowerBase64Byte(byte value)
    {
        return IsAsciiLowerDigit(value) || value is (byte)'+' or (byte)'/';
    }

    private static bool IsAsciiLowerDigit(byte value)
    {
        return value is >= (byte)'a' and <= (byte)'z'
            || value is >= (byte)'0' and <= (byte)'9';
    }

    private static bool IsWordByte(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            || value is >= (byte)'a' and <= (byte)'z'
            || value is >= (byte)'0' and <= (byte)'9'
            || value == (byte)'_';
    }

    private static bool IsWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C;
    }

    private static byte FoldAscii(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            ? (byte)(value + 0x20)
            : value;
    }
}
