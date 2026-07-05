namespace Picket.Engine;

internal sealed class DecodedInput(
    byte[] bytes,
    int[] originalStarts,
    int[] originalEnds,
    IReadOnlyList<DecodedSegment> segments)
{
    internal byte[] Bytes { get; } = bytes;

    internal int[] OriginalStarts { get; } = originalStarts;

    internal int[] OriginalEnds { get; } = originalEnds;

    internal IReadOnlyList<DecodedSegment> Segments { get; } = segments;

    internal static DecodedInput CreateOriginal(ReadOnlySpan<byte> input)
    {
        byte[] bytes = input.ToArray();
        int[] originalStarts = new int[bytes.Length];
        int[] originalEnds = new int[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            originalStarts[i] = i;
            originalEnds[i] = i + 1;
        }

        return new DecodedInput(bytes, originalStarts, originalEnds, []);
    }
}
