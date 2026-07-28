using System.Text;

namespace Picket.Engine;

/// <summary>
/// Finds bounded password assignments without constraining the password alphabet.
/// </summary>
internal static class NativePasswordAssignmentDetector
{
    private const int MaxDelimiterDistance = 32;
    private const int MaxValueLength = 512;
    private const int MinValueLength = 12;
    private static readonly string[] s_tags = ["structured:assignment", "generated-password"];

    internal static List<NativeDetectorMatch> Find(
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        var matches = new List<NativeDetectorMatch>();
        int offset = 0;
        while (offset < input.Length)
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return matches;
            }

            if (!IsIdentifierStart(input[offset]))
            {
                offset++;
                continue;
            }

            int keyStart = offset;
            offset++;
            while (offset < input.Length && IsIdentifierCharacter(input[offset]))
            {
                offset++;
            }

            int keyEnd = offset;
            if (!IsPasswordKey(input[keyStart..keyEnd])
                || !TryReadValue(input, keyEnd, out int valueStart, out int valueEnd))
            {
                continue;
            }

            ReadOnlySpan<byte> value = input[valueStart..valueEnd];
            if (!IsCandidateValue(value))
            {
                continue;
            }

            matches.Add(new NativeDetectorMatch(
                keyStart,
                valueEnd,
                valueStart,
                valueEnd,
                Encoding.UTF8.GetString(input[keyStart..valueEnd]),
                Encoding.UTF8.GetString(value),
                s_tags));
            offset = valueEnd;
        }

        return matches;
    }

    private static bool TryReadValue(
        ReadOnlySpan<byte> input,
        int offset,
        out int valueStart,
        out int valueEnd)
    {
        int delimiterLimit = Math.Min(input.Length, offset + MaxDelimiterDistance);
        while (offset < delimiterLimit && IsDelimiterPadding(input[offset]))
        {
            offset++;
        }

        if (offset >= delimiterLimit || input[offset] is not ((byte)'=' or (byte)':'))
        {
            valueStart = 0;
            valueEnd = 0;
            return false;
        }

        offset++;
        while (offset < input.Length && IsHorizontalWhitespace(input[offset]))
        {
            offset++;
        }

        byte quote = 0;
        if (offset < input.Length && input[offset] is (byte)'\'' or (byte)'"' or (byte)'`')
        {
            quote = input[offset++];
        }

        valueStart = offset;
        int limit = Math.Min(input.Length, valueStart + MaxValueLength + 1);
        while (offset < limit && !IsValueTerminator(input, offset, quote))
        {
            offset++;
        }

        valueEnd = offset;
        return valueEnd > valueStart
            && valueEnd - valueStart <= MaxValueLength
            && (quote == 0 || offset < input.Length && input[offset] == quote);
    }

    private static bool IsCandidateValue(ReadOnlySpan<byte> value)
    {
        if (value.Length < MinValueLength || IsPlaceholder(value))
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] is < 0x20 or 0x7f)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsPlaceholder(ReadOnlySpan<byte> value)
    {
        return value[0] is (byte)'$' or (byte)'%'
            || value.StartsWith("{{"u8) && value.EndsWith("}}"u8)
            || value.StartsWith("<"u8) && value.EndsWith(">"u8)
            || EqualsAsciiIgnoreCase(value, "changeme"u8)
            || EqualsAsciiIgnoreCase(value, "change_me"u8)
            || EqualsAsciiIgnoreCase(value, "example"u8)
            || EqualsAsciiIgnoreCase(value, "password"u8)
            || EqualsAsciiIgnoreCase(value, "placeholder"u8)
            || EqualsAsciiIgnoreCase(value, "redacted"u8);
    }

    private static bool IsPasswordKey(ReadOnlySpan<byte> key)
    {
        return EndsWithAsciiIgnoreCase(key, "password"u8)
            || EndsWithAsciiIgnoreCase(key, "passwd"u8);
    }

    private static bool EndsWithAsciiIgnoreCase(ReadOnlySpan<byte> value, ReadOnlySpan<byte> suffix)
    {
        return value.Length >= suffix.Length
            && EqualsAsciiIgnoreCase(value[^suffix.Length..], suffix);
    }

    private static bool EqualsAsciiIgnoreCase(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i++)
        {
            if (ToLowerAscii(left[i]) != right[i])
            {
                return false;
            }
        }

        return true;
    }

    private static byte ToLowerAscii(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            ? (byte)(value + ((byte)'a' - (byte)'A'))
            : value;
    }

    private static bool IsIdentifierStart(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or (byte)'_';
    }

    private static bool IsIdentifierCharacter(byte value)
    {
        return IsIdentifierStart(value)
            || value is >= (byte)'0' and <= (byte)'9'
            or (byte)'-'
            or (byte)'.';
    }

    private static bool IsDelimiterPadding(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\'' or (byte)'"' or (byte)'`';
    }

    private static bool IsHorizontalWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t';
    }

    private static bool IsValueTerminator(ReadOnlySpan<byte> input, int offset, byte quote)
    {
        byte value = input[offset];
        if (quote != 0)
        {
            return value == quote && !IsEscaped(input, offset);
        }

        return value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'
            or (byte)',' or (byte)';' or (byte)']' or (byte)'}';
    }

    private static bool IsEscaped(ReadOnlySpan<byte> input, int offset)
    {
        int slashCount = 0;
        for (int i = offset - 1; i >= 0 && input[i] == (byte)'\\'; i--)
        {
            slashCount++;
        }

        return (slashCount & 1) != 0;
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }
}
