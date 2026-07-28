using System.Security.Cryptography;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Passes byte input through unchanged unless it begins with a UTF-16 byte-order mark.
/// </summary>
internal sealed class Utf16BomTranscodingStream : Stream
{
    private static readonly Encoding s_bigEndian = new UnicodeEncoding(
        bigEndian: true,
        byteOrderMark: false,
        throwOnInvalidBytes: false);
    private static readonly Encoding s_littleEndian = new UnicodeEncoding(
        bigEndian: false,
        byteOrderMark: false,
        throwOnInvalidBytes: false);
    private static readonly Encoding s_utf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: false);

    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly byte[] _prefix = new byte[2];
    private readonly SourceHashingReadStream _source;
    private bool _initialized;
    private int _prefixLength;
    private int _prefixOffset;
    private Stream? _transcodingStream;

    /// <summary>
    /// Initializes a BOM-aware transcoding stream.
    /// </summary>
    /// <param name="inner">The readable source stream.</param>
    /// <param name="hash">The incremental hash that receives original source bytes.</param>
    /// <param name="leaveOpen">A value indicating whether disposal leaves the source stream open.</param>
    internal Utf16BomTranscodingStream(Stream inner, IncrementalHash hash, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(hash);
        if (!inner.CanRead)
        {
            throw new ArgumentException("The source stream must be readable.", nameof(inner));
        }

        _inner = inner;
        _leaveOpen = leaveOpen;
        _source = new SourceHashingReadStream(inner, hash, leaveOpen: true);
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
        EnsureInitialized();
        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (_transcodingStream is not null)
        {
            return _transcodingStream.Read(buffer);
        }

        int prefixRemaining = _prefixLength - _prefixOffset;
        if (prefixRemaining == 0)
        {
            return _source.Read(buffer);
        }

        int prefixCount = Math.Min(prefixRemaining, buffer.Length);
        _prefix.AsSpan(_prefixOffset, prefixCount).CopyTo(buffer);
        _prefixOffset += prefixCount;
        if (prefixCount == buffer.Length)
        {
            return prefixCount;
        }

        return prefixCount + _source.Read(buffer[prefixCount..]);
    }

    /// <inheritdoc />
    public override int ReadByte()
    {
        Span<byte> buffer = stackalloc byte[1];
        return Read(buffer) == 0 ? -1 : buffer[0];
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
            _transcodingStream?.Dispose();
            _source.Dispose();
            if (!_leaveOpen)
            {
                _inner.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private void EnsureInitialized()
    {
        if (_initialized)
        {
            return;
        }

        while (_prefixLength < _prefix.Length)
        {
            int read = _source.Read(_prefix.AsSpan(_prefixLength));
            if (read == 0)
            {
                break;
            }

            _prefixLength += read;
        }

        _initialized = true;
        if (_prefixLength != 2)
        {
            return;
        }

        Encoding? sourceEncoding = (_prefix[0], _prefix[1]) switch
        {
            (0xFF, 0xFE) => s_littleEndian,
            (0xFE, 0xFF) => s_bigEndian,
            _ => null,
        };
        if (sourceEncoding is not null)
        {
            _prefixOffset = _prefixLength;
            _transcodingStream = Encoding.CreateTranscodingStream(
                _source,
                sourceEncoding,
                s_utf8,
                leaveOpen: true);
        }
    }
}
