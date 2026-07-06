using System.Text;

namespace Picket.Engine;

internal static class CSharpStringLiteralConcatenationDecoder
{
    private const int MinimumDecodedLength = 8;

    internal static bool TryDecode(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        return TryDecodeStringConcatCall(input, start, out match)
            || TryDecodeBinaryStringConcatenation(input, start, out match);
    }

    private static bool TryDecodeStringConcatCall(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        match = default;
        if (!IsIdentifierAt(input, start, "string"u8))
        {
            return false;
        }

        int position = SkipWhitespaceAndComments(input, start + "string".Length);
        if (position >= input.Length || input[position] != (byte)'.')
        {
            return false;
        }

        position = SkipWhitespaceAndComments(input, position + 1);
        if (!IsIdentifierAt(input, position, "Concat"u8))
        {
            return false;
        }

        position = SkipWhitespaceAndComments(input, position + "Concat".Length);
        if (position >= input.Length || input[position] != (byte)'(')
        {
            return false;
        }

        position = SkipWhitespaceAndComments(input, position + 1);
        var decoded = new List<byte>();
        int literalCount = 0;
        while (position < input.Length)
        {
            if (!TryReadStringLiteral(input, position, decoded, out position))
            {
                return false;
            }

            literalCount++;
            position = SkipWhitespaceAndComments(input, position);
            if (position < input.Length && input[position] == (byte)',')
            {
                position = SkipWhitespaceAndComments(input, position + 1);
                continue;
            }

            if (position < input.Length && input[position] == (byte)')')
            {
                position++;
                break;
            }

            return false;
        }

        return TryCreateMatch(start, position, decoded, literalCount, out match);
    }

    private static bool TryDecodeBinaryStringConcatenation(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        match = default;
        var decoded = new List<byte>();
        int position = start;
        if (!TryReadStringLiteral(input, position, decoded, out position))
        {
            return false;
        }

        int literalCount = 1;
        while (true)
        {
            int operatorPosition = SkipWhitespaceAndComments(input, position);
            if (operatorPosition >= input.Length || input[operatorPosition] != (byte)'+')
            {
                break;
            }

            int nextLiteral = SkipWhitespaceAndComments(input, operatorPosition + 1);
            if (!TryReadStringLiteral(input, nextLiteral, decoded, out position))
            {
                return false;
            }

            literalCount++;
        }

        return TryCreateMatch(start, position, decoded, literalCount, out match);
    }

    private static bool TryCreateMatch(int start, int end, List<byte> decoded, int literalCount, out EncodingMatch match)
    {
        if (literalCount < 2 || decoded.Count < MinimumDecodedLength)
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, [.. decoded], DecodedEncoding.CSharpStringConcat);
        return true;
    }

    private static bool TryReadStringLiteral(ReadOnlySpan<byte> input, int start, List<byte> output, out int end)
    {
        if (start >= input.Length)
        {
            end = 0;
            return false;
        }

        if (input[start] == (byte)'@')
        {
            return TryReadVerbatimStringLiteral(input, start, output, out end);
        }

        if (input[start] == (byte)'"')
        {
            return TryReadRegularStringLiteral(input, start, output, out end);
        }

        end = 0;
        return false;
    }

    private static bool TryReadRegularStringLiteral(ReadOnlySpan<byte> input, int start, List<byte> output, out int end)
    {
        if (start + 2 < input.Length && input[start + 1] == (byte)'"' && input[start + 2] == (byte)'"')
        {
            end = 0;
            return false;
        }

        int position = start + 1;
        while (position < input.Length)
        {
            byte value = input[position];
            if (value == (byte)'"')
            {
                end = position + 1;
                return true;
            }

            if (value == (byte)'\\')
            {
                if (!TryAppendEscapedCharacter(input, position, output, out position))
                {
                    end = 0;
                    return false;
                }

                continue;
            }

            if (value is (byte)'\r' or (byte)'\n')
            {
                end = 0;
                return false;
            }

            output.Add(value);
            position++;
        }

        end = 0;
        return false;
    }

    private static bool TryReadVerbatimStringLiteral(ReadOnlySpan<byte> input, int start, List<byte> output, out int end)
    {
        if (start + 1 >= input.Length || input[start + 1] != (byte)'"')
        {
            end = 0;
            return false;
        }

        int position = start + 2;
        while (position < input.Length)
        {
            byte value = input[position];
            if (value == (byte)'"')
            {
                if (position + 1 < input.Length && input[position + 1] == (byte)'"')
                {
                    output.Add((byte)'"');
                    position += 2;
                    continue;
                }

                end = position + 1;
                return true;
            }

            output.Add(value);
            position++;
        }

        end = 0;
        return false;
    }

    private static bool TryAppendEscapedCharacter(ReadOnlySpan<byte> input, int start, List<byte> output, out int end)
    {
        if (start + 1 >= input.Length)
        {
            end = 0;
            return false;
        }

        byte value = input[start + 1];
        switch (value)
        {
            case (byte)'\'':
            case (byte)'"':
            case (byte)'\\':
                output.Add(value);
                end = start + 2;
                return true;

            case (byte)'0':
                output.Add(0);
                end = start + 2;
                return true;

            case (byte)'a':
                output.Add(0x07);
                end = start + 2;
                return true;

            case (byte)'b':
                output.Add(0x08);
                end = start + 2;
                return true;

            case (byte)'f':
                output.Add(0x0c);
                end = start + 2;
                return true;

            case (byte)'n':
                output.Add((byte)'\n');
                end = start + 2;
                return true;

            case (byte)'r':
                output.Add((byte)'\r');
                end = start + 2;
                return true;

            case (byte)'t':
                output.Add((byte)'\t');
                end = start + 2;
                return true;

            case (byte)'v':
                output.Add(0x0b);
                end = start + 2;
                return true;

            case (byte)'u':
                return TryAppendFixedHexEscape(input, start + 2, 4, output, out end);

            case (byte)'U':
                return TryAppendFixedHexEscape(input, start + 2, 8, output, out end);

            case (byte)'x':
                return TryAppendVariableHexEscape(input, start + 2, output, out end);

            default:
                end = 0;
                return false;
        }
    }

    private static bool TryAppendFixedHexEscape(
        ReadOnlySpan<byte> input,
        int start,
        int length,
        List<byte> output,
        out int end)
    {
        if (!TryReadHexCodePoint(input, start, length, out int codePoint))
        {
            end = 0;
            return false;
        }

        if (!TryAppendUtf8CodePoint(codePoint, output))
        {
            end = 0;
            return false;
        }

        end = start + length;
        return true;
    }

    private static bool TryAppendVariableHexEscape(ReadOnlySpan<byte> input, int start, List<byte> output, out int end)
    {
        int length = 0;
        while (length < 4 && start + length < input.Length && IsHex(input[start + length]))
        {
            length++;
        }

        if (length == 0 || !TryReadHexCodePoint(input, start, length, out int codePoint))
        {
            end = 0;
            return false;
        }

        if (!TryAppendUtf8CodePoint(codePoint, output))
        {
            end = 0;
            return false;
        }

        end = start + length;
        return true;
    }

    private static bool TryReadHexCodePoint(ReadOnlySpan<byte> input, int start, int length, out int codePoint)
    {
        if (start + length > input.Length)
        {
            codePoint = 0;
            return false;
        }

        codePoint = 0;
        for (int i = 0; i < length; i++)
        {
            int nibble = FromHex(input[start + i]);
            if (nibble < 0)
            {
                codePoint = 0;
                return false;
            }

            codePoint = (codePoint << 4) | nibble;
        }

        return true;
    }

    private static bool TryAppendUtf8CodePoint(int codePoint, List<byte> output)
    {
        if (codePoint is < 0 or > 0x10ffff or >= 0xd800 and <= 0xdfff)
        {
            return false;
        }

        if (codePoint <= 0x7f)
        {
            output.Add((byte)codePoint);
            return true;
        }

        output.AddRange(Encoding.UTF8.GetBytes(char.ConvertFromUtf32(codePoint)));
        return true;
    }

    private static int SkipWhitespaceAndComments(ReadOnlySpan<byte> input, int start)
    {
        int position = start;
        while (position < input.Length)
        {
            if (IsWhitespace(input[position]))
            {
                position++;
                continue;
            }

            if (position + 1 < input.Length && input[position] == (byte)'/' && input[position + 1] == (byte)'/')
            {
                position += 2;
                while (position < input.Length && input[position] is not ((byte)'\r' or (byte)'\n'))
                {
                    position++;
                }

                continue;
            }

            if (position + 1 < input.Length && input[position] == (byte)'/' && input[position + 1] == (byte)'*')
            {
                position += 2;
                while (position + 1 < input.Length && (input[position] != (byte)'*' || input[position + 1] != (byte)'/'))
                {
                    position++;
                }

                position = Math.Min(position + 2, input.Length);
                continue;
            }

            break;
        }

        return position;
    }

    private static bool IsIdentifierAt(ReadOnlySpan<byte> input, int start, ReadOnlySpan<byte> identifier)
    {
        if (start < 0 || start + identifier.Length > input.Length)
        {
            return false;
        }

        if (start > 0 && IsIdentifierPart(input[start - 1]))
        {
            return false;
        }

        if (!input[start..(start + identifier.Length)].SequenceEqual(identifier))
        {
            return false;
        }

        return start + identifier.Length >= input.Length || !IsIdentifierPart(input[start + identifier.Length]);
    }

    private static bool IsIdentifierPart(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9'
            or (byte)'_';
    }

    private static bool IsWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0b or 0x0c;
    }

    private static bool IsHex(byte value)
    {
        return FromHex(value) >= 0;
    }

    private static int FromHex(byte value)
    {
        return value switch
        {
            >= (byte)'0' and <= (byte)'9' => value - (byte)'0',
            >= (byte)'A' and <= (byte)'F' => value - (byte)'A' + 10,
            >= (byte)'a' and <= (byte)'f' => value - (byte)'a' + 10,
            _ => -1,
        };
    }
}
