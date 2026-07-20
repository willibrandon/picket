using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Picket.Engine;

internal static class SecretDecoder
{
    private const int MinimumBase64Length = 16;
    private const int MinimumHexLength = 32;

    public static DecodedInput? Decode(DecodedInput input, bool enableCSharpStringConcatenation = false)
    {
        ArgumentNullException.ThrowIfNull(input);

        List<EncodingMatch> matches = FindMatches(input.Bytes, enableCSharpStringConcatenation);
        if (matches.Count == 0)
        {
            return null;
        }

        var output = new List<byte>(input.Bytes.Length);
        var sourceMap = new List<DecodedSourceMapSegment>(matches.Count * 2 + 1);
        var segments = new List<DecodedSegment>(matches.Count);
        int position = 0;
        foreach (EncodingMatch match in matches)
        {
            CopyOriginal(input, position, match.Start, output, sourceMap);

            DecodedEncoding inheritedEncodings = DecodedEncoding.None;
            int inheritedDepth = 0;
            IReadOnlyList<string> inheritedDecodePath = [];
            foreach (DecodedSegment segment in input.Segments)
            {
                if (segment.OverlapsDecoded(match.Start, match.End))
                {
                    inheritedEncodings |= segment.Encodings;
                    if (segment.Depth >= inheritedDepth)
                    {
                        inheritedDepth = segment.Depth;
                        inheritedDecodePath = segment.DecodePath;
                    }
                }
            }

            int decodedStart = output.Count;
            if (!input.TryMapRange(match.Start, match.End, out int originalStart, out int originalEnd))
            {
                throw new InvalidOperationException("Decoded input source mapping is incomplete.");
            }

            output.AddRange(match.Decoded);
            DecodedInput.AppendSegment(sourceMap, new DecodedSourceMapSegment(
                decodedStart,
                output.Count,
                originalStart,
                originalEnd,
                isLinear: false));

            segments.Add(new DecodedSegment(
                decodedStart,
                output.Count,
                originalStart,
                originalEnd,
                inheritedEncodings | match.Encoding,
                inheritedDepth + 1,
                CreateDecodePath(inheritedDecodePath, match.Encoding)));
            position = match.End;
        }

        CopyOriginal(input, position, input.Bytes.Length, output, sourceMap);
        return new DecodedInput([.. output], sourceMap, segments);
    }

    private static List<string> CreateDecodePath(IReadOnlyList<string> inheritedDecodePath, DecodedEncoding encoding)
    {
        var decodePath = new List<string>(inheritedDecodePath.Count + 1);
        decodePath.AddRange(inheritedDecodePath);
        decodePath.Add(GetDecodeName(encoding));
        return decodePath;
    }

    private static string GetDecodeName(DecodedEncoding encoding)
    {
        return encoding switch
        {
            DecodedEncoding.Percent => "percent",
            DecodedEncoding.Unicode => "unicode",
            DecodedEncoding.Hex => "hex",
            DecodedEncoding.Base64 => "base64",
            DecodedEncoding.CSharpStringConcat => "csharp-string-concat",
            _ => "unknown",
        };
    }

    private static List<EncodingMatch> FindMatches(ReadOnlySpan<byte> input, bool enableCSharpStringConcatenation)
    {
        var matches = new List<EncodingMatch>();
        int position = 0;
        while (position < input.Length)
        {
            if (enableCSharpStringConcatenation
                && CSharpStringLiteralConcatenationDecoder.TryDecode(input, position, out EncodingMatch csharpMatch))
            {
                matches.Add(csharpMatch);
                position = csharpMatch.End;
                continue;
            }

            if (input[position] == (byte)'%' && TryDecodePercent(input, position, out EncodingMatch percentMatch))
            {
                matches.Add(percentMatch);
                position = percentMatch.End;
                continue;
            }

            if (TryDecodeUnicode(input, position, out EncodingMatch unicodeMatch))
            {
                matches.Add(unicodeMatch);
                position = unicodeMatch.End;
                continue;
            }

            if (IsHex(input[position])
                && TryDecodeHex(input, position, FindHexEnd(input, position), out EncodingMatch hexMatch))
            {
                matches.Add(hexMatch);
                position = hexMatch.End;
                continue;
            }

            if (IsBase64(input[position]))
            {
                int base64End = FindBase64End(input, position);
                if (TryDecodeBase64(input, position, base64End, out EncodingMatch base64Match))
                {
                    matches.Add(base64Match);
                    position = base64Match.End;
                    continue;
                }

                position = base64End;
                continue;
            }

            position++;
        }

        return matches;
    }

    private static bool TryDecodeUnicode(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        return TryDecodeUnicodeCodePoints(input, start, out match)
            || TryDecodeUnicodeEscapes(input, start, out match);
    }

    private static bool TryDecodeUnicodeCodePoints(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        var decoded = new List<byte>();
        while (TryReadUnicodeCodePoint(input, end, out int nextEnd, out int codePoint))
        {
            if (!TryAppendUtf8CodePoint(codePoint, decoded))
            {
                match = default;
                return false;
            }

            end = nextEnd;
            int whitespaceEnd = end;
            while (whitespaceEnd < input.Length && IsAsciiWhiteSpace(input[whitespaceEnd]))
            {
                whitespaceEnd++;
            }

            if (!TryReadUnicodeCodePoint(input, whitespaceEnd, out _, out _))
            {
                break;
            }

            end = whitespaceEnd;
        }

        if (decoded.Count == 0)
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, [.. decoded], DecodedEncoding.Unicode);
        return true;
    }

    private static bool TryDecodeUnicodeEscapes(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        var decoded = new List<byte>();
        while (TryReadUnicodeEscape(input, end, out int nextEnd, out int codePoint))
        {
            if (!TryAppendUtf8CodePoint(codePoint, decoded))
            {
                match = default;
                return false;
            }

            end = nextEnd;
        }

        if (decoded.Count == 0)
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, [.. decoded], DecodedEncoding.Unicode);
        return true;
    }

    private static bool TryDecodePercent(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        var decoded = new List<byte>();
        while (end + 2 < input.Length && input[end] == (byte)'%' && TryReadHexByte(input[end + 1], input[end + 2], out byte value))
        {
            decoded.Add(value);
            end += 3;
        }

        if (decoded.Count == 0 || !IsPrintableUtf8(CollectionsMarshal.AsSpan(decoded)))
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, [.. decoded], DecodedEncoding.Percent);
        return true;
    }

    private static bool TryDecodeHex(ReadOnlySpan<byte> input, int start, int end, out EncodingMatch match)
    {
        bool hasDigit = false;
        for (int i = start; i < end; i++)
        {
            hasDigit |= input[i] is >= (byte)'0' and <= (byte)'9';
        }

        int length = end - start;
        if (length < MinimumHexLength || length % 2 != 0 || !hasDigit)
        {
            match = default;
            return false;
        }

        byte[] decoded = new byte[length / 2];
        for (int i = 0; i < decoded.Length; i++)
        {
            if (!TryReadHexByte(input[start + i * 2], input[start + i * 2 + 1], out decoded[i]))
            {
                match = default;
                return false;
            }
        }

        if (!IsPrintableUtf8(decoded))
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, decoded, DecodedEncoding.Hex);
        return true;
    }

    private static int FindHexEnd(ReadOnlySpan<byte> input, int start)
    {
        int end = start;
        while (end < input.Length && IsHex(input[end]))
        {
            end++;
        }

        return end;
    }

    private static bool TryDecodeBase64(ReadOnlySpan<byte> input, int start, int end, out EncodingMatch match)
    {
        bool hasLikelyBase64Char = false;
        for (int i = start; i < end; i++)
        {
            hasLikelyBase64Char |= IsLikelyBase64Char(input[i]);
        }

        int length = end - start;
        if (length < MinimumBase64Length || !hasLikelyBase64Char)
        {
            match = default;
            return false;
        }

        byte[] encoded = input[start..end].ToArray();
        if (!TryDecodeBase64Bytes(encoded, out byte[]? decoded) || !IsPrintableUtf8(decoded))
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, decoded, DecodedEncoding.Base64);
        return true;
    }

    private static int FindBase64End(ReadOnlySpan<byte> input, int start)
    {
        int end = start;
        while (end < input.Length && IsBase64(input[end]))
        {
            end++;
        }

        while (end < input.Length && input[end] == (byte)'=')
        {
            end++;
        }

        return end;
    }

    private static bool TryDecodeBase64Bytes(byte[] encoded, [NotNullWhen(true)] out byte[]? decoded)
    {
        decoded = null;
        byte[] buffer = new byte[Base64.GetMaxDecodedFromUtf8Length(encoded.Length)];
        OperationStatus status = Base64.DecodeFromUtf8(encoded, buffer, out int consumed, out int written);
        if (status == OperationStatus.Done && consumed == encoded.Length)
        {
            decoded = buffer.AsSpan(0, written).ToArray();
            return true;
        }

        string text = Encoding.ASCII.GetString(encoded);
        string padded = PadBase64Url(text);
        try
        {
            decoded = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
            return true;
        }
        catch (FormatException)
        {
            decoded = null;
            return false;
        }
    }

    private static string PadBase64Url(string value)
    {
        int remainder = value.Length % 4;
        return remainder == 0 ? value : value.PadRight(value.Length + 4 - remainder, '=');
    }

    private static void CopyOriginal(
        DecodedInput input,
        int start,
        int end,
        List<byte> output,
        List<DecodedSourceMapSegment> sourceMap)
    {
        if (start == end)
        {
            return;
        }

        int outputStart = output.Count;
        output.AddRange(input.Bytes.AsSpan(start, end - start));
        input.AppendSourceMap(start, end, outputStart, sourceMap);
    }

    private static bool TryReadHexByte(byte high, byte low, out byte value)
    {
        int highNibble = FromHex(high);
        int lowNibble = FromHex(low);
        if (highNibble < 0 || lowNibble < 0)
        {
            value = 0;
            return false;
        }

        value = (byte)((highNibble << 4) | lowNibble);
        return true;
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

    private static bool IsHex(byte value)
    {
        return FromHex(value) >= 0;
    }

    private static bool IsBase64(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9'
            or (byte)'+'
            or (byte)'/'
            or (byte)'-'
            or (byte)'_';
    }

    private static bool IsLikelyBase64Char(byte value)
    {
        return value is >= (byte)'0' and <= (byte)'9'
            or (byte)'+'
            or (byte)'/'
            or (byte)'-'
            or (byte)'_';
    }

    private static bool IsPrintableUtf8(ReadOnlySpan<byte> value)
    {
        while (!value.IsEmpty)
        {
            OperationStatus status = Rune.DecodeFromUtf8(value, out Rune rune, out int consumed);
            if (status != OperationStatus.Done
                || rune.Value == 0
                || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control)
            {
                return false;
            }

            value = value[consumed..];
        }

        return true;
    }

    private static bool TryReadUnicodeCodePoint(ReadOnlySpan<byte> input, int start, out int end, out int codePoint)
    {
        if (start + 6 > input.Length || input[start] != (byte)'U' || input[start + 1] != (byte)'+')
        {
            end = 0;
            codePoint = 0;
            return false;
        }

        if (!TryReadHexCodePoint(input, start + 2, out codePoint))
        {
            end = 0;
            return false;
        }

        end = start + 6;
        return true;
    }

    private static bool TryReadUnicodeEscape(ReadOnlySpan<byte> input, int start, out int end, out int codePoint)
    {
        if (start >= input.Length || input[start] != (byte)'\\')
        {
            end = 0;
            codePoint = 0;
            return false;
        }

        int prefixEnd = start + 1;
        if (prefixEnd < input.Length && input[prefixEnd] == (byte)'\\')
        {
            prefixEnd++;
        }

        if (prefixEnd + 5 > input.Length || input[prefixEnd] is not ((byte)'u' or (byte)'U'))
        {
            end = 0;
            codePoint = 0;
            return false;
        }

        if (!TryReadHexCodePoint(input, prefixEnd + 1, out codePoint))
        {
            end = 0;
            return false;
        }

        end = prefixEnd + 5;
        return true;
    }

    private static bool TryReadHexCodePoint(ReadOnlySpan<byte> input, int start, out int codePoint)
    {
        if (start + 4 > input.Length)
        {
            codePoint = 0;
            return false;
        }

        codePoint = 0;
        for (int i = 0; i < 4; i++)
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

    private static bool TryAppendUtf8CodePoint(int codePoint, List<byte> decoded)
    {
        if (codePoint is < 0 or > 0x10ffff or >= 0xd800 and <= 0xdfff)
        {
            return false;
        }

        var rune = new Rune(codePoint);
        if (rune.Value == 0 || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control)
        {
            return false;
        }

        if (codePoint <= 0x7f)
        {
            decoded.Add((byte)codePoint);
            return true;
        }

        decoded.AddRange(Encoding.UTF8.GetBytes(char.ConvertFromUtf32(codePoint)));
        return true;
    }

    private static bool IsAsciiWhiteSpace(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r' or 0x0b or 0x0c;
    }
}
