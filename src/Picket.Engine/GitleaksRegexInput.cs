using System.Buffers;
using System.Text;
using System.Text.Unicode;

namespace Picket.Engine;

internal sealed class GitleaksRegexInput(byte[] bytes, int[] replacementStarts, int sourceLength)
{
    private const byte ReplacementByte0 = 0xEF;
    private const byte ReplacementByte1 = 0xBF;
    private const byte ReplacementByte2 = 0xBD;

    internal byte[] Bytes { get; } = bytes;

    internal static GitleaksRegexInput? Normalize(ReadOnlySpan<byte> source)
    {
        if (Utf8.IsValid(source))
        {
            return null;
        }

        int replacementCount = 0;
        long normalizedLength = source.Length;
        int sourceOffset = 0;
        while (sourceOffset < source.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(source[sourceOffset..], out _, out int consumed);
            if (status == OperationStatus.Done)
            {
                sourceOffset += consumed;
                continue;
            }

            replacementCount++;
            normalizedLength += 2;
            sourceOffset++;
        }

        if (normalizedLength > Array.MaxLength)
        {
            throw new InvalidDataException("UTF-8 replacement would exceed the maximum supported scan buffer size.");
        }

        byte[] normalized = GC.AllocateUninitializedArray<byte>((int)normalizedLength);
        int[] replacementStarts = GC.AllocateUninitializedArray<int>(replacementCount);
        sourceOffset = 0;
        int normalizedOffset = 0;
        int replacementIndex = 0;
        while (sourceOffset < source.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(source[sourceOffset..], out _, out int consumed);
            if (status == OperationStatus.Done)
            {
                source.Slice(sourceOffset, consumed).CopyTo(normalized.AsSpan(normalizedOffset));
                sourceOffset += consumed;
                normalizedOffset += consumed;
                continue;
            }

            replacementStarts[replacementIndex++] = normalizedOffset;
            normalized[normalizedOffset] = ReplacementByte0;
            normalized[normalizedOffset + 1] = ReplacementByte1;
            normalized[normalizedOffset + 2] = ReplacementByte2;
            sourceOffset++;
            normalizedOffset += 3;
        }

        return new GitleaksRegexInput(normalized, replacementStarts, source.Length);
    }

    internal void MapRange(int start, int end, out int sourceStart, out int sourceEnd)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(end, Bytes.Length);
        if (end < start)
        {
            throw new ArgumentOutOfRangeException(nameof(end), end, "End must be greater than or equal to start.");
        }

        sourceStart = MapOffset(start);
        sourceEnd = start == end ? sourceStart : MapOffset(end - 1) + 1;
    }

    private int MapOffset(int normalizedOffset)
    {
        if (normalizedOffset == Bytes.Length)
        {
            return sourceLength;
        }

        int replacementIndex = Array.BinarySearch(replacementStarts, normalizedOffset);
        if (replacementIndex >= 0)
        {
            return replacementStarts[replacementIndex] - (replacementIndex * 2);
        }

        int completedReplacementCount = ~replacementIndex;
        if (completedReplacementCount > 0)
        {
            int precedingReplacementIndex = completedReplacementCount - 1;
            int precedingReplacementStart = replacementStarts[precedingReplacementIndex];
            if (normalizedOffset < precedingReplacementStart + 3)
            {
                return precedingReplacementStart - (precedingReplacementIndex * 2);
            }
        }

        return normalizedOffset - (completedReplacementCount * 2);
    }
}
