namespace Picket.Engine;

internal sealed class DecodedInput(
    byte[] bytes,
    IReadOnlyList<DecodedSourceMapSegment> sourceMap,
    IReadOnlyList<DecodedSegment> segments)
{
    internal byte[] Bytes { get; } = bytes;

    internal IReadOnlyList<DecodedSourceMapSegment> SourceMap { get; } = sourceMap;

    internal IReadOnlyList<DecodedSegment> Segments { get; } = segments;

    internal static DecodedInput CreateOriginal(ReadOnlySpan<byte> input)
    {
        byte[] bytes = input.ToArray();
        IReadOnlyList<DecodedSourceMapSegment> sourceMap = bytes.Length == 0
            ? []
            : [new DecodedSourceMapSegment(0, bytes.Length, 0, bytes.Length, isLinear: true)];
        return new DecodedInput(bytes, sourceMap, []);
    }

    internal void AppendSourceMap(int start, int end, int outputStart, List<DecodedSourceMapSegment> destination)
    {
        foreach (DecodedSourceMapSegment segment in SourceMap)
        {
            if (segment.DecodedStart >= end)
            {
                break;
            }

            if (!segment.OverlapsDecoded(start, end))
            {
                continue;
            }

            int overlapStart = Math.Max(start, segment.DecodedStart);
            int overlapEnd = Math.Min(end, segment.DecodedEnd);
            int copiedStart = outputStart + overlapStart - start;
            int copiedEnd = copiedStart + overlapEnd - overlapStart;
            int originalStart = segment.IsLinear
                ? segment.OriginalStart + overlapStart - segment.DecodedStart
                : segment.OriginalStart;
            int originalEnd = segment.IsLinear
                ? segment.OriginalStart + overlapEnd - segment.DecodedStart
                : segment.OriginalEnd;
            AppendSegment(destination, new DecodedSourceMapSegment(
                copiedStart,
                copiedEnd,
                originalStart,
                originalEnd,
                segment.IsLinear));
        }
    }

    internal bool TryMapRange(int start, int end, out int originalStart, out int originalEnd)
    {
        originalStart = int.MaxValue;
        originalEnd = 0;
        bool found = false;
        foreach (DecodedSourceMapSegment segment in SourceMap)
        {
            if (segment.DecodedStart >= end)
            {
                break;
            }

            if (!segment.OverlapsDecoded(start, end))
            {
                continue;
            }

            int overlapStart = Math.Max(start, segment.DecodedStart);
            int overlapEnd = Math.Min(end, segment.DecodedEnd);
            int mappedStart = segment.IsLinear
                ? segment.OriginalStart + overlapStart - segment.DecodedStart
                : segment.OriginalStart;
            int mappedEnd = segment.IsLinear
                ? segment.OriginalStart + overlapEnd - segment.DecodedStart
                : segment.OriginalEnd;
            originalStart = Math.Min(originalStart, mappedStart);
            originalEnd = Math.Max(originalEnd, mappedEnd);
            found = true;
        }

        return found;
    }

    internal static void AppendSegment(
        List<DecodedSourceMapSegment> destination,
        DecodedSourceMapSegment segment)
    {
        if (destination.Count != 0)
        {
            DecodedSourceMapSegment previous = destination[^1];
            if (previous.IsLinear
                && segment.IsLinear
                && previous.DecodedEnd == segment.DecodedStart
                && previous.OriginalEnd == segment.OriginalStart)
            {
                destination[^1] = new DecodedSourceMapSegment(
                    previous.DecodedStart,
                    segment.DecodedEnd,
                    previous.OriginalStart,
                    segment.OriginalEnd,
                    isLinear: true);
                return;
            }
        }

        destination.Add(segment);
    }
}
