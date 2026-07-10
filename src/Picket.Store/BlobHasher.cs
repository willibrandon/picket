using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Store;

/// <summary>
/// Computes stable content identities for scanned blobs and cache keys.
/// </summary>
public static class BlobHasher
{
    private const int StreamBufferSize = 128 * 1024;
    private const string LowerHex = "0123456789abcdef";

    /// <summary>
    /// Computes a lowercase SHA-256 hash for a byte span.
    /// </summary>
    /// <param name="content">The content to hash.</param>
    /// <returns>The lowercase hexadecimal SHA-256 hash.</returns>
    public static string ComputeSha256Hex(ReadOnlySpan<byte> content)
    {
        byte[] hash = SHA256.HashData(content);
        return ToLowerHex(hash);
    }

    /// <summary>
    /// Computes a lowercase SHA-256 hash for UTF-8 text.
    /// </summary>
    /// <param name="text">The text to hash as UTF-8.</param>
    /// <returns>The lowercase hexadecimal SHA-256 hash.</returns>
    public static string ComputeSha256Hex(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return ComputeSha256Hex(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Computes a lowercase SHA-256 hash by reading a stream to completion without closing it.
    /// </summary>
    /// <param name="content">The readable content stream at the position where hashing should begin.</param>
    /// <param name="cancellationToken">A token checked between bounded stream reads.</param>
    /// <returns>The lowercase hexadecimal SHA-256 hash.</returns>
    public static string ComputeSha256Hex(Stream content, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanRead)
        {
            throw new ArgumentException("The content stream must be readable.", nameof(content));
        }

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = content.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
            }

            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    internal static string RequireSha256Hex(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != SHA256.HashSizeInBytes * 2)
        {
            throw new ArgumentException("The value must be a 64-character SHA-256 hexadecimal hash.", parameterName);
        }

        for (int i = 0; i < value.Length; i++)
        {
            if (!char.IsAsciiHexDigit(value[i]))
            {
                throw new ArgumentException("The value must be a 64-character SHA-256 hexadecimal hash.", parameterName);
            }
        }

        return value.ToLowerInvariant();
    }

    internal static string ToLowerHex(ReadOnlySpan<byte> bytes)
    {
        return string.Create(bytes.Length * 2, bytes.ToArray(), static (chars, hash) =>
        {
            for (int i = 0; i < hash.Length; i++)
            {
                byte value = hash[i];
                chars[i * 2] = LowerHex[value >> 4];
                chars[(i * 2) + 1] = LowerHex[value & 0x0F];
            }
        });
    }
}
