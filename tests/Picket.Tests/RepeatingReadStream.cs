namespace Picket.Tests;

/// <summary>
/// Provides a non-seekable stream that returns one repeated byte.
/// </summary>
internal sealed class RepeatingReadStream(long length, byte value) : Stream
{
    private long _remaining = length >= 0 ? length : throw new ArgumentOutOfRangeException(nameof(length));

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush()
    {
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        return Read(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        if (buffer.Length == 0 || _remaining == 0)
        {
            return 0;
        }

        int read = (int)Math.Min(buffer.Length, _remaining);
        buffer[..read].Fill(value);
        _remaining -= read;
        return read;
    }

    /// <inheritdoc />
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}
