namespace Picket.Engine;

internal readonly struct DecodedSegment(
    int decodedStart,
    int decodedEnd,
    int originalStart,
    int originalEnd,
    DecodedEncoding encodings,
    int depth,
    IReadOnlyList<string> decodePath)
{
    internal int DecodedStart { get; } = decodedStart;

    internal int DecodedEnd { get; } = decodedEnd;

    internal int OriginalStart { get; } = originalStart;

    internal int OriginalEnd { get; } = originalEnd;

    internal DecodedEncoding Encodings { get; } = encodings;

    internal int Depth { get; } = depth;

    internal IReadOnlyList<string> DecodePath { get; } = decodePath;

    internal bool OverlapsDecoded(int start, int end)
    {
        return start < DecodedEnd && end > DecodedStart;
    }
}
