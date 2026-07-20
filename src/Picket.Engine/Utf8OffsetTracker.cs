using System.Text;

namespace Picket.Engine;

/// <summary>
/// Converts monotonically increasing UTF-16 indices to UTF-8 byte offsets without a per-character map.
/// </summary>
internal sealed class Utf8OffsetTracker(string source)
{
    private readonly string _source = source ?? throw new ArgumentNullException(nameof(source));
    private int _byteOffset;
    private int _characterOffset;

    internal int GetByteOffset(int characterOffset)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(characterOffset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(characterOffset, _source.Length);
        if (characterOffset < _characterOffset)
        {
            throw new ArgumentOutOfRangeException(nameof(characterOffset), "Offsets must be requested in source order.");
        }

        _byteOffset += Encoding.UTF8.GetByteCount(_source.AsSpan(_characterOffset, characterOffset - _characterOffset));
        _characterOffset = characterOffset;
        return _byteOffset;
    }
}
