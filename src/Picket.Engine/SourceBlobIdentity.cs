using System.Security.Cryptography;

namespace Picket.Engine;

internal sealed class SourceBlobIdentity(ReadOnlyMemory<byte> input)
{
    private const string LowerHex = "0123456789abcdef";

    private readonly ReadOnlyMemory<byte> _input = input;
    private string? _sha256;

    internal string Sha256 => _sha256 ??= CreateSha256Hex(_input.Span);

    private static string CreateSha256Hex(ReadOnlySpan<byte> content)
    {
        byte[] hash = SHA256.HashData(content);
        return string.Create(hash.Length * 2, hash, static (chars, bytes) =>
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte value = bytes[i];
                chars[i * 2] = LowerHex[value >> 4];
                chars[(i * 2) + 1] = LowerHex[value & 0x0F];
            }
        });
    }
}
