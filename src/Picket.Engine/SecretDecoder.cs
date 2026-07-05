using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Picket.Engine;

internal static class SecretDecoder
{
    private const int MinimumBase64Length = 16;
    private const int MinimumHexLength = 32;

    public static DecodedInput? Decode(DecodedInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        List<EncodingMatch> matches = FindMatches(input.Bytes);
        if (matches.Count == 0)
        {
            return null;
        }

        var output = new List<byte>(input.Bytes.Length);
        var starts = new List<int>(input.Bytes.Length);
        var ends = new List<int>(input.Bytes.Length);
        var segments = new List<DecodedSegment>(matches.Count);
        int position = 0;
        foreach (EncodingMatch match in matches)
        {
            CopyOriginal(input, position, match.Start, output, starts, ends);

            DecodedEncoding inheritedEncodings = DecodedEncoding.None;
            int inheritedDepth = 0;
            foreach (DecodedSegment segment in input.Segments)
            {
                if (segment.OverlapsDecoded(match.Start, match.End))
                {
                    inheritedEncodings |= segment.Encodings;
                    inheritedDepth = Math.Max(inheritedDepth, segment.Depth);
                }
            }

            int decodedStart = output.Count;
            int originalStart = input.OriginalStarts[match.Start];
            int originalEnd = input.OriginalEnds[match.End - 1];
            output.AddRange(match.Decoded);
            for (int i = 0; i < match.Decoded.Length; i++)
            {
                starts.Add(originalStart);
                ends.Add(originalEnd);
            }

            segments.Add(new DecodedSegment(
                decodedStart,
                output.Count,
                originalStart,
                originalEnd,
                inheritedEncodings | match.Encoding,
                inheritedDepth + 1));
            position = match.End;
        }

        CopyOriginal(input, position, input.Bytes.Length, output, starts, ends);
        return new DecodedInput([.. output], [.. starts], [.. ends], segments);
    }

    private static List<EncodingMatch> FindMatches(ReadOnlySpan<byte> input)
    {
        var matches = new List<EncodingMatch>();
        int position = 0;
        while (position < input.Length)
        {
            if (input[position] == (byte)'%' && TryDecodePercent(input, position, out EncodingMatch percentMatch))
            {
                matches.Add(percentMatch);
                position = percentMatch.End;
                continue;
            }

            if (IsHex(input[position]) && TryDecodeHex(input, position, out EncodingMatch hexMatch))
            {
                matches.Add(hexMatch);
                position = hexMatch.End;
                continue;
            }

            if (IsBase64(input[position]) && TryDecodeBase64(input, position, out EncodingMatch base64Match))
            {
                matches.Add(base64Match);
                position = base64Match.End;
                continue;
            }

            position++;
        }

        return matches;
    }

    private static bool TryDecodePercent(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        var decoded = new List<byte>();
        while (end + 2 < input.Length && input[end] == (byte)'%' && TryReadHexByte(input[end + 1], input[end + 2], out byte value))
        {
            if (!IsPrintableAscii(value))
            {
                match = default;
                return false;
            }

            decoded.Add(value);
            end += 3;
        }

        if (decoded.Count == 0)
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, [.. decoded], DecodedEncoding.Percent);
        return true;
    }

    private static bool TryDecodeHex(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        bool hasDigit = false;
        while (end < input.Length && IsHex(input[end]))
        {
            hasDigit |= input[end] is >= (byte)'0' and <= (byte)'9';
            end++;
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
            if (!TryReadHexByte(input[start + i * 2], input[start + i * 2 + 1], out decoded[i])
                || !IsPrintableAscii(decoded[i]))
            {
                match = default;
                return false;
            }
        }

        match = new EncodingMatch(start, end, decoded, DecodedEncoding.Hex);
        return true;
    }

    private static bool TryDecodeBase64(ReadOnlySpan<byte> input, int start, out EncodingMatch match)
    {
        int end = start;
        bool hasLikelyBase64Char = false;
        while (end < input.Length && IsBase64(input[end]))
        {
            hasLikelyBase64Char |= IsLikelyBase64Char(input[end]);
            end++;
        }

        while (end < input.Length && input[end] == (byte)'=')
        {
            end++;
        }

        int length = end - start;
        if (length < MinimumBase64Length || !hasLikelyBase64Char)
        {
            match = default;
            return false;
        }

        byte[] encoded = input[start..end].ToArray();
        if (!TryDecodeBase64Bytes(encoded, out byte[]? decoded) || !IsPrintableAscii(decoded))
        {
            match = default;
            return false;
        }

        match = new EncodingMatch(start, end, decoded, DecodedEncoding.Base64);
        return true;
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
        List<int> starts,
        List<int> ends)
    {
        for (int i = start; i < end; i++)
        {
            output.Add(input.Bytes[i]);
            starts.Add(input.OriginalStarts[i]);
            ends.Add(input.OriginalEnds[i]);
        }
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

    private static bool IsPrintableAscii(ReadOnlySpan<byte> value)
    {
        foreach (byte b in value)
        {
            if (!IsPrintableAscii(b))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsPrintableAscii(byte value)
    {
        return value is > 0x08 and < 0x7f;
    }
}
