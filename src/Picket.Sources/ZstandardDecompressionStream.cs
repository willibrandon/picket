using System.Buffers;
using System.Runtime.InteropServices;

namespace Picket.Sources;

/// <summary>
/// Reads one or more concatenated zstandard frames through a bounded native decoder.
/// </summary>
internal sealed class ZstandardDecompressionStream : Stream
{
    private const int DefaultInputBufferSize = 64 * 1024;
    private const int DefaultMaximumWindowLog = 26;
    private const int MaximumWindowLog = 30;
    private const int MinimumWindowLog = 10;
    private const int WindowLogMaxParameter = 100;

    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly ZstandardDecompressionHandle _context;
    private byte[]? _inputBuffer;
    private int _inputLength;
    private int _inputOffset;
    private bool _atFrameBoundary;
    private bool _disposed;
    private bool _sourceCompleted;

    internal ZstandardDecompressionStream(Stream stream, long? maximumWindowBytes, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("stream must be readable", nameof(stream));
        }

        _stream = stream;
        _leaveOpen = leaveOpen;
        _context = ZstandardDecompressionHandle.Create();
        _inputBuffer = ArrayPool<byte>.Shared.Rent(DefaultInputBufferSize);

        int maximumWindowLog = GetMaximumWindowLog(maximumWindowBytes);
        nuint result = ZstandardNativeMethods.SetDecompressionParameter(
            _context.DangerousGetHandle(),
            WindowLogMaxParameter,
            maximumWindowLog);
        ThrowIfError(result);
    }

    public override bool CanRead => !_disposed;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("offset and count exceed the buffer length");
        }

        return Read(buffer.AsSpan(offset, count));
    }

    public override unsafe int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

        byte[] inputBuffer = _inputBuffer!;
        while (true)
        {
            if (_atFrameBoundary)
            {
                if (_inputOffset < _inputLength)
                {
                    _atFrameBoundary = false;
                }
                else if (_sourceCompleted)
                {
                    return 0;
                }
                else
                {
                    _inputLength = _stream.Read(inputBuffer);
                    _inputOffset = 0;
                    _sourceCompleted = _inputLength == 0;
                    if (_sourceCompleted)
                    {
                        return 0;
                    }

                    _atFrameBoundary = false;
                }
            }

            if (_inputOffset == _inputLength && !_sourceCompleted)
            {
                _inputLength = _stream.Read(inputBuffer);
                _inputOffset = 0;
                _sourceCompleted = _inputLength == 0;
            }

            fixed (byte* source = inputBuffer)
            fixed (byte* destination = buffer)
            {
                var input = new ZstandardInputBuffer(source + _inputOffset, (nuint)(_inputLength - _inputOffset));
                var output = new ZstandardOutputBuffer(destination, (nuint)buffer.Length);
                nuint result = ZstandardNativeMethods.DecompressStream(
                    _context.DangerousGetHandle(),
                    ref output,
                    ref input);
                ThrowIfError(result);

                _inputOffset += checked((int)input._position);
                _atFrameBoundary = result == 0;
                int bytesWritten = checked((int)output._position);
                if (bytesWritten > 0)
                {
                    return bytesWritten;
                }

                if (_sourceCompleted)
                {
                    if (_atFrameBoundary)
                    {
                        return 0;
                    }

                    throw new InvalidDataException("zstandard content ended before the frame was complete");
                }

                if (input._position == 0 && _inputOffset < _inputLength)
                {
                    throw new InvalidDataException("zstandard decompression made no progress");
                }
            }
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            if (disposing)
            {
                _context.Dispose();
                if (!_leaveOpen)
                {
                    _stream.Dispose();
                }

                byte[]? inputBuffer = _inputBuffer;
                _inputBuffer = null;
                if (inputBuffer is not null)
                {
                    ArrayPool<byte>.Shared.Return(inputBuffer, clearArray: true);
                }
            }
        }

        base.Dispose(disposing);
    }

    private static int GetMaximumWindowLog(long? maximumWindowBytes)
    {
        if (!maximumWindowBytes.HasValue)
        {
            return DefaultMaximumWindowLog;
        }

        long bytes = Math.Max(1, maximumWindowBytes.Value);
        int windowLog = checked((int)(64 - long.LeadingZeroCount(bytes - 1)));
        return Math.Clamp(windowLog, MinimumWindowLog, MaximumWindowLog);
    }

    private static void ThrowIfError(nuint result)
    {
        if (ZstandardNativeMethods.IsError(result) != 0)
        {
            string errorName = Marshal.PtrToStringUTF8(ZstandardNativeMethods.GetErrorName(result)) ?? "unknown error";
            throw new InvalidDataException($"invalid or unsupported zstandard content: {errorName}");
        }
    }
}
