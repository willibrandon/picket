using System.Security.Cryptography;

namespace Picket.Sources;

/// <summary>
/// Appends every byte read from a source stream to an incremental hash.
/// </summary>
internal sealed class SourceHashingReadStream : Stream
{
    private readonly IncrementalHash _hash;
    private readonly Stream _inner;
    private readonly bool _leaveOpen;

    /// <summary>
    /// Initializes a hashing wrapper over a readable stream.
    /// </summary>
    /// <param name="inner">The readable source stream.</param>
    /// <param name="hash">The incremental hash that receives source bytes.</param>
    /// <param name="leaveOpen">A value indicating whether disposal leaves the source stream open.</param>
    internal SourceHashingReadStream(Stream inner, IncrementalHash hash, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(hash);
        if (!inner.CanRead)
        {
            throw new ArgumentException("The source stream must be readable.", nameof(inner));
        }

        _inner = inner;
        _hash = hash;
        _leaveOpen = leaveOpen;
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
        int read = _inner.Read(buffer);
        if (read != 0)
        {
            _hash.AppendData(buffer[..read]);
        }

        return read;
    }

    /// <inheritdoc />
    public override int ReadByte()
    {
        int value = _inner.ReadByte();
        if (value >= 0)
        {
            Span<byte> source = stackalloc byte[1];
            source[0] = (byte)value;
            _hash.AppendData(source);
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

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
