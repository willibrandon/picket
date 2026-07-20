namespace Picket.Sources;

/// <summary>
/// Exposes at most one byte beyond a configured input limit without owning the underlying stream.
/// </summary>
internal sealed class MaxLengthReadStream : Stream
{
    private readonly Stream _inner;
    private readonly long _maxLength;
    private long _bytesRead;

    /// <summary>
    /// Initializes a bounded probe over a readable stream.
    /// </summary>
    /// <param name="inner">The readable stream.</param>
    /// <param name="maxLength">The maximum accepted input length.</param>
    internal MaxLengthReadStream(Stream inner, long maxLength)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfNegative(maxLength);
        if (!inner.CanRead)
        {
            throw new ArgumentException("The input stream must be readable.", nameof(inner));
        }

        _inner = inner;
        _maxLength = maxLength;
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => false;

    /// <summary>
    /// Gets a value indicating whether the input contained more than the configured maximum length.
    /// </summary>
    internal bool LimitExceeded { get; private set; }

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
        int readLength = GetReadLength(buffer.Length);
        if (readLength == 0)
        {
            return 0;
        }

        int read = _inner.Read(buffer[..readLength]);
        RecordRead(read);
        return read;
    }

    /// <inheritdoc />
    public override int ReadByte()
    {
        if (GetReadLength(1) == 0)
        {
            return -1;
        }

        int value = _inner.ReadByte();
        if (value >= 0)
        {
            RecordRead(1);
        }

        return value;
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

    private int GetReadLength(int requestedLength)
    {
        long probeLength = _maxLength == long.MaxValue ? long.MaxValue : _maxLength + 1;
        long remaining = probeLength - _bytesRead;
        return remaining <= 0 ? 0 : (int)Math.Min(requestedLength, remaining);
    }

    private void RecordRead(int count)
    {
        _bytesRead += count;
        LimitExceeded = _bytesRead > _maxLength;
    }
}
