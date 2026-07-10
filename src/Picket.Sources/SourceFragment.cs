using System.Buffers;

namespace Picket.Sources;

/// <summary>
/// Owns a bounded fragment of source content and its position in the original source.
/// </summary>
public sealed class SourceFragment : IDisposable
{
    private byte[]? _buffer;
    private readonly int _length;

    internal SourceFragment(byte[] buffer, int length, long startOffset, int startLine, int startColumn)
    {
        _buffer = buffer;
        _length = length;
        StartOffset = startOffset;
        StartLine = startLine;
        StartColumn = startColumn;
    }

    /// <summary>
    /// Gets the fragment bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Content
    {
        get
        {
            ObjectDisposedException.ThrowIf(_buffer is null, this);
            return _buffer.AsMemory(0, _length);
        }
    }

    /// <summary>
    /// Gets the zero-based byte offset of the fragment in the original source.
    /// </summary>
    public long StartOffset { get; }

    /// <summary>
    /// Gets the one-based line where the fragment starts.
    /// </summary>
    public int StartLine { get; }

    /// <summary>
    /// Gets the one-based column where the fragment starts.
    /// </summary>
    public int StartColumn { get; }

    /// <summary>
    /// Returns the secret-bearing pooled buffer owned by this fragment.
    /// </summary>
    public void Dispose()
    {
        byte[]? buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}
