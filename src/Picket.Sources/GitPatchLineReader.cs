using System.Buffers;

namespace Picket.Sources;

/// <summary>
/// Reads git patch output as raw byte lines while preserving line terminators.
/// </summary>
internal sealed class GitPatchLineReader(Stream stream, Func<bool>? isCancellationRequested = null) : IDisposable
{
    private const int BufferSize = 64 * 1024;

    private readonly byte[] _buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
    private readonly Func<bool>? _isCancellationRequested = isCancellationRequested;
    private Stream? _stream = stream ?? throw new ArgumentNullException(nameof(stream));
    private int _length;
    private int _offset;

    internal byte[]? ReadLine()
    {
        ArrayBufferWriter<byte>? accumulated = null;
        while (true)
        {
            if (_offset == _length)
            {
                if (_isCancellationRequested?.Invoke() == true)
                {
                    return null;
                }

                _length = _stream!.Read(_buffer, 0, _buffer.Length);
                _offset = 0;
                if (_length == 0)
                {
                    return accumulated?.WrittenSpan.ToArray();
                }
            }

            ReadOnlySpan<byte> available = _buffer.AsSpan(_offset, _length - _offset);
            int newlineIndex = available.IndexOf((byte)'\n');
            int segmentLength = newlineIndex < 0 ? available.Length : newlineIndex + 1;
            if (accumulated is null && newlineIndex >= 0)
            {
                _offset += segmentLength;
                return available[..segmentLength].ToArray();
            }

            accumulated ??= new ArrayBufferWriter<byte>(Math.Max(segmentLength, BufferSize));
            available[..segmentLength].CopyTo(accumulated.GetSpan(segmentLength));
            accumulated.Advance(segmentLength);
            _offset += segmentLength;
            if (newlineIndex >= 0)
            {
                return accumulated.WrittenSpan.ToArray();
            }
        }
    }

    /// <summary>
    /// Releases the pooled read buffer.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _stream, null) is not null)
        {
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
        }
    }
}
