using System.Text;

namespace Picket.Engine;

internal sealed class KeywordPrefilter(IReadOnlyList<byte[]> keywords)
{
    private IReadOnlyList<byte[]> Keywords { get; } = keywords ?? throw new ArgumentNullException(nameof(keywords));

    internal static KeywordPrefilter Create(IReadOnlyList<string> keywords)
    {
        ArgumentNullException.ThrowIfNull(keywords);

        var encodedKeywords = new List<byte[]>(keywords.Count);
        foreach (string keyword in keywords)
        {
            if (string.IsNullOrEmpty(keyword))
            {
                continue;
            }

            byte[] encodedKeyword = Encoding.UTF8.GetBytes(keyword);
            FoldAsciiInPlace(encodedKeyword);
            encodedKeywords.Add(encodedKeyword);
        }

        return new KeywordPrefilter(encodedKeywords);
    }

    internal bool IsCandidate(ReadOnlySpan<byte> input)
    {
        if (Keywords.Count == 0)
        {
            return true;
        }

        foreach (byte[] keyword in Keywords)
        {
            if (ContainsAsciiIgnoreCase(input, keyword))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsAsciiIgnoreCase(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyword)
    {
        if (keyword.IsEmpty)
        {
            return true;
        }

        if (keyword.Length > input.Length)
        {
            return false;
        }

        byte first = keyword[0];
        byte upperFirst = ToUpperAscii(first);
        int offset = 0;
        while (offset <= input.Length - keyword.Length)
        {
            int relativeIndex = first == upperFirst
                ? input[offset..].IndexOf(first)
                : input[offset..].IndexOfAny(first, upperFirst);
            if (relativeIndex < 0)
            {
                return false;
            }

            int start = offset + relativeIndex;
            if (start > input.Length - keyword.Length)
            {
                return false;
            }

            if (StartsWithAsciiIgnoreCase(input[start..], keyword))
            {
                return true;
            }

            offset = start + 1;
        }

        return false;
    }

    private static bool StartsWithAsciiIgnoreCase(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyword)
    {
        for (int index = 0; index < keyword.Length; index++)
        {
            if (FoldAscii(input[index]) != FoldAscii(keyword[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static byte FoldAscii(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z'
            ? (byte)(value + 0x20)
            : value;
    }

    private static void FoldAsciiInPlace(byte[] value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            value[index] = FoldAscii(value[index]);
        }
    }

    private static byte ToUpperAscii(byte value)
    {
        return value is >= (byte)'a' and <= (byte)'z'
            ? (byte)(value - 0x20)
            : value;
    }
}
