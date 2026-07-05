namespace Picket.Engine;

internal readonly struct EncodingMatch(
    int start,
    int end,
    byte[] decoded,
    DecodedEncoding encoding)
{
    internal int Start { get; } = start;

    internal int End { get; } = end;

    internal byte[] Decoded { get; } = decoded;

    internal DecodedEncoding Encoding { get; } = encoding;
}
