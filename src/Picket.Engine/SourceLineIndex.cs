namespace Picket.Engine;

internal sealed class SourceLineIndex
{
    private readonly int _inputLength;
    private readonly int[] _lineStarts;
    private readonly int _startColumn;
    private readonly int _startLine;

    private SourceLineIndex(int inputLength, int[] lineStarts, int startLine, int startColumn)
    {
        _inputLength = inputLength;
        _lineStarts = lineStarts;
        _startLine = startLine;
        _startColumn = startColumn;
    }

    internal static SourceLineIndex Create(ReadOnlySpan<byte> input, int startLine = 1, int startColumn = 1)
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

        return new SourceLineIndex(input.Length, lineStarts, startLine, startColumn);
    }

    internal SourcePosition FromExclusiveEndOffset(int startOffset, int endOffset)
    {
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

        int column = lineIndex == 0
            ? offset - _lineStarts[lineIndex] + _startColumn
            : offset - _lineStarts[lineIndex] + 2;
        return new SourcePosition(_startLine + lineIndex, column);
    }
}
