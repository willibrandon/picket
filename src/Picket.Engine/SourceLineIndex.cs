using System.Buffers;
using System.Text;

namespace Picket.Engine;

internal sealed class SourceLineIndex
{
    private readonly int _inputLength;
    private readonly int[] _lineStarts;
    private readonly int[] _utf8ContinuationOffsets;
    private readonly int _startColumn;
    private readonly int _startLine;

    private SourceLineIndex(
        int inputLength,
        int[] lineStarts,
        int[] utf8ContinuationOffsets,
        int startLine,
        int startColumn,
        FindingPositionKind positionKind)
    {
        _inputLength = inputLength;
        _lineStarts = lineStarts;
        _utf8ContinuationOffsets = utf8ContinuationOffsets;
        _startLine = startLine;
        _startColumn = startColumn;
        PositionKind = positionKind;
    }

    internal FindingPositionKind PositionKind { get; }

    internal static SourceLineIndex Create(
        ReadOnlySpan<byte> input,
        int startLine = 1,
        int startColumn = 1,
        FindingPositionKind positionKind = FindingPositionKind.GitleaksUtf8BytesInclusive)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(startLine, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(startColumn, 1);

        int lineCount = 1;
        foreach (byte value in input)
        {
            if (value == (byte)'\n')
            {
                lineCount++;
            }
        }

        int[] lineStarts = GC.AllocateUninitializedArray<int>(lineCount);
        lineStarts[0] = 0;
        int lineIndex = 1;
        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == (byte)'\n')
            {
                lineStarts[lineIndex++] = i + 1;
            }
        }

        int[] utf8ContinuationOffsets = positionKind == FindingPositionKind.UnicodeCodePointsExclusive
            ? CreateUtf8ContinuationOffsets(input)
            : [];
        return new SourceLineIndex(input.Length, lineStarts, utf8ContinuationOffsets, startLine, startColumn, positionKind);
    }

    internal SourcePosition FromExclusiveEndOffset(int startOffset, int endOffset)
    {
        if (PositionKind == FindingPositionKind.UnicodeCodePointsExclusive)
        {
            return FromOffset(endOffset);
        }

        return FromOffset(endOffset <= startOffset ? startOffset : endOffset - 1);
    }

    internal SourcePosition FromOffset(int offset)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, _inputLength);

        int lineIndex = Array.BinarySearch(_lineStarts, offset);
        if (lineIndex < 0)
        {
            lineIndex = ~lineIndex - 1;
        }

        int column;
        if (PositionKind == FindingPositionKind.UnicodeCodePointsExclusive)
        {
            int continuationCount = CountUtf8ContinuationOffsets(_lineStarts[lineIndex], offset);
            int firstColumn = lineIndex == 0 ? _startColumn : 1;
            column = offset - _lineStarts[lineIndex] - continuationCount + firstColumn;
        }
        else
        {
            column = lineIndex == 0
                ? offset - _lineStarts[lineIndex] + _startColumn
                : offset - _lineStarts[lineIndex] + 2;
        }

        return new SourcePosition(_startLine + lineIndex, column);
    }

    private static int[] CreateUtf8ContinuationOffsets(ReadOnlySpan<byte> input)
    {
        List<int>? offsets = null;
        int position = 0;
        while (position < input.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(input[position..], out _, out int consumed);
            if (status != OperationStatus.Done)
            {
                position++;
                continue;
            }

            if (consumed > 1)
            {
                offsets ??= [];
                for (int i = 1; i < consumed; i++)
                {
                    offsets.Add(position + i);
                }
            }

            position += consumed;
        }

        return offsets is null ? [] : [.. offsets];
    }

    private int CountUtf8ContinuationOffsets(int start, int end)
    {
        if (_utf8ContinuationOffsets.Length == 0 || start >= end)
        {
            return 0;
        }

        int startIndex = LowerBound(_utf8ContinuationOffsets, start);
        int endIndex = LowerBound(_utf8ContinuationOffsets, end);
        return endIndex - startIndex;
    }

    private static int LowerBound(int[] values, int value)
    {
        int lower = 0;
        int upper = values.Length;
        while (lower < upper)
        {
            int middle = lower + ((upper - lower) / 2);
            if (values[middle] < value)
            {
                lower = middle + 1;
            }
            else
            {
                upper = middle;
            }
        }

        return lower;
    }
}
