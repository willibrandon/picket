using System.Security.Cryptography;
using System.Text;

namespace Picket.Store;

/// <summary>
/// Computes stable content identities for scanned blobs and cache keys.
/// </summary>
public static class BlobHasher
{
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
