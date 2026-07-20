using System.Text;

namespace Picket.Engine;

internal sealed class KeywordPrefilter(List<byte[]> asciiKeywords, List<string> unicodeKeywords)
{
    private readonly List<byte[]> _asciiKeywords = asciiKeywords ?? throw new ArgumentNullException(nameof(asciiKeywords));
    private readonly List<string> _unicodeKeywords = unicodeKeywords ?? throw new ArgumentNullException(nameof(unicodeKeywords));

    internal static KeywordPrefilter Create(IReadOnlyList<string> keywords)
    {
        ArgumentNullException.ThrowIfNull(keywords);

        var asciiKeywords = new List<byte[]>(keywords.Count);
        var unicodeKeywords = new List<string>();
        foreach (string keyword in keywords)
        {
            if (string.IsNullOrEmpty(keyword))
            {
                continue;
            }

            if (IsAscii(keyword))
            {
                byte[] encodedKeyword = Encoding.UTF8.GetBytes(keyword);
                FoldAsciiInPlace(encodedKeyword);
                asciiKeywords.Add(encodedKeyword);
            }
            else
            {
                unicodeKeywords.Add(keyword.ToLowerInvariant());
            }
        }

        return new KeywordPrefilter(asciiKeywords, unicodeKeywords);
    }

    internal bool IsCandidate(ReadOnlySpan<byte> input)
    {
        if (_asciiKeywords.Count == 0 && _unicodeKeywords.Count == 0)
        {
            return true;
        }

        foreach (byte[] keyword in _asciiKeywords)
        {
            if (ContainsAsciiIgnoreCase(input, keyword))
            {
                return true;
            }
        }

        if (_unicodeKeywords.Count == 0)
        {
            return false;
        }

        string normalizedInput = Encoding.UTF8.GetString(input).ToLowerInvariant();
        foreach (string keyword in _unicodeKeywords)
        {
            if (normalizedInput.Contains(keyword, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAscii(string value)
    {
        foreach (char character in value)
        {
            if (!char.IsAscii(character))
            {
                return false;
            }
        }

        return true;
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
