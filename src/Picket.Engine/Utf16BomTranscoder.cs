using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Transcodes BOM-marked UTF-16 input into pooled UTF-8 storage.
/// </summary>
internal static class Utf16BomTranscoder
{
    private const int CancellationCheckMask = 0xFFF;

    /// <summary>
    /// Determines whether input begins with a UTF-16 byte-order mark.
    /// </summary>
    internal static bool HasBom(ReadOnlySpan<byte> input)
    {
        return input.Length >= 2
            && ((input[0] == 0xFF && input[1] == 0xFE)
                || (input[0] == 0xFE && input[1] == 0xFF));
    }

    /// <summary>
    /// Creates a pooled UTF-8 buffer for BOM-marked UTF-16 input.
    /// </summary>
    /// <param name="input">The original encoded bytes.</param>
    /// <param name="isCancellationRequested">An optional cancellation predicate.</param>
    /// <param name="canceled">Set when transcoding stopped because cancellation was requested.</param>
    /// <returns>A pooled transcoded buffer, or <see langword="null" /> when the input is not BOM-marked UTF-16.</returns>
    internal static Utf16BomBuffer? Create(
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested,
        out bool canceled)
    {
        canceled = false;
        if (!HasBom(input))
        {
            return null;
        }

        bool bigEndian = input[0] == 0xFE;
        ReadOnlySpan<byte> payload = input[2..];
        long maximumLength = ((long)payload.Length + 1) / 2 * 3;
        if (maximumLength > Array.MaxLength)
        {
            throw new InvalidOperationException("BOM-marked UTF-16 input is too large to transcode.");
        }

        byte[] output = ArrayPool<byte>.Shared.Rent(Math.Max(1, (int)maximumLength));
        int inputOffset = 0;
        int outputOffset = 0;
        try
        {
            while (inputOffset < payload.Length)
            {
                if ((inputOffset & CancellationCheckMask) == 0
                    && isCancellationRequested?.Invoke() == true)
                {
                    canceled = true;
                    ArrayPool<byte>.Shared.Return(output, clearArray: true);
                    return null;
                }

                Rune rune;
                if (payload.Length - inputOffset < 2)
                {
                    rune = Rune.ReplacementChar;
                    inputOffset = payload.Length;
                }
                else
                {
                    char first = (char)ReadCodeUnit(payload[inputOffset..], bigEndian);
                    inputOffset += 2;
                    if (char.IsHighSurrogate(first))
                    {
                        if (payload.Length - inputOffset >= 2)
                        {
                            char second = (char)ReadCodeUnit(payload[inputOffset..], bigEndian);
                            if (char.IsLowSurrogate(second))
                            {
                                rune = new Rune(first, second);
                                inputOffset += 2;
                            }
                            else
                            {
                                rune = Rune.ReplacementChar;
                            }
                        }
                        else
                        {
                            rune = Rune.ReplacementChar;
                        }
                    }
                    else
                    {
                        rune = char.IsLowSurrogate(first)
                            ? Rune.ReplacementChar
                            : new Rune(first);
                    }
                }

                outputOffset += rune.EncodeToUtf8(output.AsSpan(outputOffset));
            }

            if (isCancellationRequested?.Invoke() == true)
            {
                canceled = true;
                ArrayPool<byte>.Shared.Return(output, clearArray: true);
                return null;
            }

            return new Utf16BomBuffer(output, outputOffset);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(output, clearArray: true);
            throw;
        }
    }

    private static ushort ReadCodeUnit(ReadOnlySpan<byte> value, bool bigEndian)
    {
        return bigEndian
            ? BinaryPrimitives.ReadUInt16BigEndian(value)
            : BinaryPrimitives.ReadUInt16LittleEndian(value);
    }
}
