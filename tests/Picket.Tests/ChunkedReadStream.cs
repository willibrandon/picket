namespace Picket.Tests;

/// <summary>
/// Restricts each source read to a configured number of bytes.
/// </summary>
internal sealed class ChunkedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly int _maximumReadLength;

    /// <summary>
    /// Initializes a chunk-limited readable stream.
    /// </summary>
    /// <param name="inner">The readable source stream.</param>
    /// <param name="maximumReadLength">The maximum bytes returned by one read.</param>
    internal ChunkedReadStream(Stream inner, int maximumReadLength)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumReadLength);
        _inner = inner;
        _maximumReadLength = maximumReadLength;
    }

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
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, buffer.Length - offset);
        return Read(buffer.AsSpan(offset, count));
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        return _inner.Read(buffer[..Math.Min(buffer.Length, _maximumReadLength)]);
    }

    /// <inheritdoc />
    public override int ReadByte()
    {
        return _inner.ReadByte();
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

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
