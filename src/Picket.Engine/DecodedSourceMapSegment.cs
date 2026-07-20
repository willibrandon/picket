namespace Picket.Engine;

internal readonly struct DecodedSourceMapSegment(
    int decodedStart,
    int decodedEnd,
    int originalStart,
    int originalEnd,
    bool isLinear)
{
    internal int DecodedStart { get; } = decodedStart;

    internal int DecodedEnd { get; } = decodedEnd;

    internal int OriginalStart { get; } = originalStart;

    internal int OriginalEnd { get; } = originalEnd;

    internal bool IsLinear { get; } = isLinear;

    internal bool OverlapsDecoded(int start, int end)
    {
        return start < DecodedEnd && end > DecodedStart;
    }
}
