using System.Buffers;

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
    /// <summary>
    /// Gets the default primary fragment size in bytes.
    /// </summary>
    public const int DefaultBufferSize = 100_000;

    /// <summary>
    /// Gets the default maximum safe-boundary read-ahead in bytes.
    /// </summary>
    public const int DefaultMaxPeekBytes = 25_000;

    private readonly int _bufferSize;
    private readonly bool _leaveOpen;
    private readonly int _maxPeekBytes;
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
    public SourceFragmentReader(
        Stream stream,
        int bufferSize = DefaultBufferSize,
        int maxPeekBytes = DefaultMaxPeekBytes,
        bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);
        ArgumentOutOfRangeException.ThrowIfNegative(maxPeekBytes);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The source stream must be readable.", nameof(stream));
        }

        _ = checked(bufferSize + maxPeekBytes);
        _stream = stream;
        _bufferSize = bufferSize;
        _maxPeekBytes = maxPeekBytes;
        _leaveOpen = leaveOpen;
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
            int length = ReadPrimary(buffer, cancellationToken);
            if (length == 0)
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                return null;
            }

            if (length == _bufferSize && !EndsAtSafeBoundary(buffer.AsSpan(0, length)))
            {
                length = ReadToSafeBoundary(buffer, length, cancellationToken);
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

    private int ReadPrimary(byte[] buffer, CancellationToken cancellationToken)
    {
        int length = 0;
        while (length < _bufferSize)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = _stream!.Read(buffer, length, _bufferSize - length);
            if (read == 0)
            {
                break;
            }

            length += read;
        }

        return length;
    }

    private int ReadToSafeBoundary(byte[] buffer, int length, CancellationToken cancellationToken)
    {
        int newlineCount = CountTrailingNewlines(buffer.AsSpan(0, length));
        while (length - _bufferSize < _maxPeekBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int value = _stream!.ReadByte();
            if (value < 0)
            {
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
            else
            {
                _nextColumn++;
            }
        }
    }
}
