using System.Globalization;

namespace Picket.Sources;

/// <summary>
/// Wraps a stream and fails as soon as reads exceed a configured byte cap.
/// </summary>
internal sealed class CappedReadStream(Stream inner, long maxBytes, string target) : Stream
{
    private readonly Stream _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly long _maxBytes = maxBytes;
    private readonly string _target = target;
    private long _bytesRead;

    /// <inheritdoc />
    public override bool CanRead => _inner.CanRead;

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
        ArgumentOutOfRangeException.ThrowIfNegative(buffer.Length);

        if (buffer.Length == 0)
        {
            return 0;
        }

        if (_bytesRead >= _maxBytes)
        {
            Span<byte> probe = stackalloc byte[1];
            int extra = _inner.Read(probe);
            if (extra == 0)
            {
                return 0;
            }

            ThrowTooLarge();
        }

        int allowed = (int)Math.Min(buffer.Length, _maxBytes - _bytesRead);
        int read = _inner.Read(buffer[..allowed]);
        _bytesRead += read;
        return read;
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length == 0)
        {
            return 0;
        }

        if (_bytesRead >= _maxBytes)
        {
            byte[] probe = GC.AllocateUninitializedArray<byte>(1);
            int extra = await _inner.ReadAsync(probe.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (extra == 0)
            {
                return 0;
            }

            ThrowTooLarge();
        }

        int allowed = (int)Math.Min(buffer.Length, _maxBytes - _bytesRead);
        int read = await _inner.ReadAsync(buffer[..allowed], cancellationToken).ConfigureAwait(false);
        _bytesRead += read;
        return read;
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

    private void ThrowTooLarge()
    {
        throw new RemoteMetadataTooLargeException(
            string.Create(
                CultureInfo.InvariantCulture,
                $"skipping {_target} because remote metadata response exceeded the {_maxBytes} byte metadata cap"));
    }
}
