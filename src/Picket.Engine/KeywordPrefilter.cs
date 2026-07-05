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

            encodedKeywords.Add(Encoding.UTF8.GetBytes(keyword));
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

        int lastStart = input.Length - keyword.Length;
        for (int start = 0; start <= lastStart; start++)
        {
            if (StartsWithAsciiIgnoreCase(input[start..], keyword))
            {
                return true;
            }
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
}
