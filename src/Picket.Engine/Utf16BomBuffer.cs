using System.Buffers;

namespace Picket.Engine;

/// <summary>
/// Owns a pooled UTF-8 buffer produced from BOM-marked UTF-16 input.
/// </summary>
internal sealed class Utf16BomBuffer(byte[] buffer, int length) : IDisposable
{
    private byte[]? _buffer = buffer;

    /// <summary>
    /// Gets the transcoded UTF-8 content.
    /// </summary>
    internal ReadOnlyMemory<byte> Memory =>
        _buffer is null
            ? throw new ObjectDisposedException(nameof(Utf16BomBuffer))
            : _buffer.AsMemory(0, length);

    /// <summary>
    /// Clears and returns the owned buffer to the shared pool.
    /// </summary>
    public void Dispose()
    {
        byte[]? ownedBuffer = Interlocked.Exchange(ref _buffer, null);
        if (ownedBuffer is not null)
        {
            ArrayPool<byte>.Shared.Return(ownedBuffer, clearArray: true);
        }
    }
}
