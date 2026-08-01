using System.Buffers;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Reads a source stream as bounded fragments using Gitleaks-compatible safe boundaries.
/// </summary>
/// <remarks>
/// The default sizes and blank-line read-ahead reproduce the pinned Gitleaks source reader at
/// <see href="https://github.com/gitleaks/gitleaks/blob/4c232b5014f7618360bd992b4c489cb055881c6b/sources/file.go#L21" />
/// and <see href="https://github.com/gitleaks/gitleaks/blob/4c232b5014f7618360bd992b4c489cb055881c6b/sources/common.go#L16" />.
/// </remarks>
public sealed class SourceFragmentReader : IDisposable
{
    private const int GitleaksBufferedReaderSize = 4 * 1024;

    /// <summary>
    /// Gets the default primary fragment size in bytes.
    /// </summary>
    public const int DefaultBufferSize = 100_000;

    /// <summary>
    /// Gets the default maximum safe-boundary read-ahead in bytes.
    /// </summary>
    public const int DefaultMaxPeekBytes = 25_000;

    private readonly int _bufferSize;
    private readonly byte[] _carry = new byte[3];
    private readonly bool _leaveOpen;
    private readonly int _maxPeekBytes;
    private readonly byte[] _readBuffer = new byte[GitleaksBufferedReaderSize];
    private readonly bool _useUnicodeCodePointColumns;
    private int _carryLength;
    private int _readEnd;
    private int _readStart;
    private Stream? _stream;
    private int _nextColumn = 1;
    private int _nextLine = 1;
    private long _nextOffset;

    /// <summary>
    /// Initializes a reader over a source stream.
    /// </summary>
    /// <param name="stream">The readable source stream.</param>
    /// <param name="bufferSize">The primary fragment size in bytes.</param>
    /// <param name="maxPeekBytes">The maximum bytes read beyond the primary fragment while seeking a safe boundary.</param>
    /// <param name="leaveOpen">A value indicating whether disposing this reader leaves <paramref name="stream" /> open.</param>
    /// <param name="useUnicodeCodePointColumns">A value indicating whether columns are counted as UTF-8 code points.</param>
    public SourceFragmentReader(
        Stream stream,
        int bufferSize = DefaultBufferSize,
        int maxPeekBytes = DefaultMaxPeekBytes,
        bool leaveOpen = false,
        bool useUnicodeCodePointColumns = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);
        ArgumentOutOfRangeException.ThrowIfNegative(maxPeekBytes);
        if (useUnicodeCodePointColumns)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 4);
        }

        if (!stream.CanRead)
        {
            throw new ArgumentException("The source stream must be readable.", nameof(stream));
        }

        _ = checked(bufferSize + maxPeekBytes);
        _stream = stream;
        _bufferSize = bufferSize;
        _maxPeekBytes = maxPeekBytes;
        _leaveOpen = leaveOpen;
        _useUnicodeCodePointColumns = useUnicodeCodePointColumns;
    }

    /// <summary>
    /// Reads the next source fragment, or returns <see langword="null" /> at the end of the stream.
    /// </summary>
    /// <param name="cancellationToken">A token checked during bounded reads.</param>
    /// <returns>An owned fragment that the caller must dispose, or <see langword="null" /> at end of stream.</returns>
    public SourceFragment? ReadNext(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_stream is null, this);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] buffer = ArrayPool<byte>.Shared.Rent(checked(_bufferSize + _maxPeekBytes));
        try
        {
            int primaryLength = ReadPrimary(buffer, cancellationToken, out bool reachedEnd);
            if (primaryLength == 0)
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                return null;
            }

            int length = primaryLength;
            if (!EndsAtSafeBoundary(buffer.AsSpan(0, length)))
            {
                length = ReadToSafeBoundary(buffer, length, primaryLength, cancellationToken, ref reachedEnd);
            }

            if (_useUnicodeCodePointColumns && !reachedEnd)
            {
                length = PreserveIncompleteUtf8Suffix(buffer, length);
            }

            var fragment = new SourceFragment(buffer, length, _nextOffset, _nextLine, _nextColumn);
            AdvancePosition(buffer.AsSpan(0, length));
            return fragment;
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            throw;
        }
    }

    /// <summary>
    /// Disposes the underlying stream unless this reader was configured to leave it open.
    /// </summary>
    public void Dispose()
    {
        Stream? stream = Interlocked.Exchange(ref _stream, null);
        if (!_leaveOpen)
        {
            stream?.Dispose();
        }

        _carry.AsSpan().Clear();
        _readBuffer.AsSpan().Clear();
        _carryLength = 0;
        _readEnd = 0;
        _readStart = 0;
    }

    private static bool EndsAtSafeBoundary(ReadOnlySpan<byte> content)
    {
        return CountTrailingNewlines(content) >= 2;
    }

    private static int CountTrailingNewlines(ReadOnlySpan<byte> content)
    {
        int newlineCount = 0;
        for (int i = content.Length - 1; i >= 0; i--)
        {
            byte value = content[i];
            if (value == (byte)'\n')
            {
                newlineCount++;
            }
            else if (!IsWhitespace(value))
            {
                break;
            }
        }

        return newlineCount;
    }

    private static bool IsWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r';
    }

    private int ReadPrimary(
        byte[] buffer,
        CancellationToken cancellationToken,
        out bool reachedEnd)
    {
        reachedEnd = false;
        int length = _carryLength;
        _carry.AsSpan(0, _carryLength).CopyTo(buffer);
        _carryLength = 0;
        cancellationToken.ThrowIfCancellationRequested();
        length += ReadBuffered(buffer.AsSpan(length, _bufferSize - length), out reachedEnd);

        return length;
    }

    private int ReadBuffered(Span<byte> destination, out bool reachedEnd)
    {
        reachedEnd = false;
        if (_readStart < _readEnd)
        {
            int length = Math.Min(destination.Length, _readEnd - _readStart);
            _readBuffer.AsSpan(_readStart, length).CopyTo(destination);
            _readStart += length;
            return length;
        }

        _readStart = 0;
        _readEnd = 0;
        if (destination.Length >= _readBuffer.Length)
        {
            int length = _stream!.Read(destination);
            reachedEnd = length == 0;
            return length;
        }

        _readEnd = _stream!.Read(_readBuffer);
        if (_readEnd == 0)
        {
            reachedEnd = true;
            return 0;
        }

        int copied = Math.Min(destination.Length, _readEnd);
        _readBuffer.AsSpan(0, copied).CopyTo(destination);
        _readStart = copied;
        return copied;
    }

    private int ReadBufferedByte()
    {
        if (_readStart >= _readEnd)
        {
            _readStart = 0;
            _readEnd = _stream!.Read(_readBuffer);
            if (_readEnd == 0)
            {
                return -1;
            }
        }

        return _readBuffer[_readStart++];
    }

    private int PreserveIncompleteUtf8Suffix(byte[] buffer, int length)
    {
        if (length == 0)
        {
            return 0;
        }

        int sequenceStart = length - 1;
        while (sequenceStart > 0
            && IsUtf8ContinuationByte(buffer[sequenceStart])
            && length - sequenceStart < 4)
        {
            sequenceStart--;
        }

        int expectedLength = GetUtf8SequenceLength(buffer[sequenceStart]);
        int actualLength = length - sequenceStart;
        if (expectedLength <= actualLength || expectedLength == 1)
        {
            return length;
        }

        for (int i = sequenceStart + 1; i < length; i++)
        {
            if (!IsUtf8ContinuationByte(buffer[i]))
            {
                return length;
            }
        }

        _carryLength = actualLength;
        buffer.AsSpan(sequenceStart, actualLength).CopyTo(_carry);
        return sequenceStart;
    }

    private static bool IsUtf8ContinuationByte(byte value)
    {
        return (value & 0xC0) == 0x80;
    }

    private static int GetUtf8SequenceLength(byte value)
    {
        if (value < 0x80)
        {
            return 1;
        }

        if ((value & 0xE0) == 0xC0)
        {
            return 2;
        }

        if ((value & 0xF0) == 0xE0)
        {
            return 3;
        }

        return (value & 0xF8) == 0xF0 ? 4 : 1;
    }

    private int ReadToSafeBoundary(
        byte[] buffer,
        int length,
        int primaryLength,
        CancellationToken cancellationToken,
        ref bool reachedEnd)
    {
        int newlineCount = CountTrailingNewlines(buffer.AsSpan(0, length));
        while (length - primaryLength < _maxPeekBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int value = ReadBufferedByte();
            if (value < 0)
            {
                reachedEnd = true;
                break;
            }

            byte current = (byte)value;
            buffer[length++] = current;
            if (current == (byte)'\n')
            {
                newlineCount++;
                if (newlineCount >= 2)
                {
                    break;
                }
            }
            else if (!IsWhitespace(current))
            {
                newlineCount = 0;
            }
        }

        return length;
    }

    private void AdvancePosition(ReadOnlySpan<byte> content)
    {
        _nextOffset += content.Length;
        for (int i = 0; i < content.Length; i++)
        {
            if (content[i] == (byte)'\n')
            {
                _nextLine++;
                _nextColumn = 1;
            }
            else if (_useUnicodeCodePointColumns)
            {
                OperationStatus status = Rune.DecodeFromUtf8(content[i..], out _, out int bytesConsumed);
                _nextColumn++;
                if (status == OperationStatus.Done)
                {
                    i += bytesConsumed - 1;
                }
            }
            else
            {
                _nextColumn++;
            }
        }
    }
}
