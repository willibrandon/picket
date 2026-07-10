using System.Security.Cryptography;
using System.Text;

namespace Picket.Store;

internal static class ProtectedStatePayload
{
    private const int NonceByteLength = 12;
    private const int TagByteLength = 16;
    private const string Prefix = "enc:v1:";

    internal static byte[] DeriveKey(ReadOnlySpan<byte> authenticationKey, ReadOnlySpan<byte> purpose)
    {
        return HMACSHA256.HashData(authenticationKey, purpose);
    }

    internal static string Protect(ReadOnlySpan<byte> key, string value)
    {
        if (value.Length == 0)
        {
            return string.Empty;
        }

        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        byte[] nonce = new byte[NonceByteLength];
        byte[] tag = new byte[TagByteLength];
        byte[] ciphertext = new byte[plaintext.Length];
        RandomNumberGenerator.Fill(nonce);

        try
        {
            using var aes = new AesGcm(key, TagByteLength);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            byte[] payload = new byte[nonce.Length + tag.Length + ciphertext.Length];
            nonce.CopyTo(payload, 0);
            tag.CopyTo(payload, nonce.Length);
            ciphertext.CopyTo(payload, nonce.Length + tag.Length);
            return string.Concat(Prefix, Convert.ToBase64String(payload));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    internal static bool TryUnprotect(ReadOnlySpan<byte> key, string value, out string unprotected)
    {
        unprotected = string.Empty;
        if (value.Length == 0)
        {
            return true;
        }

        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            byte[] payload = Convert.FromBase64String(value[Prefix.Length..]);
            if (payload.Length <= NonceByteLength + TagByteLength)
            {
                return false;
            }

            ReadOnlySpan<byte> nonce = payload.AsSpan(0, NonceByteLength);
            ReadOnlySpan<byte> tag = payload.AsSpan(NonceByteLength, TagByteLength);
            ReadOnlySpan<byte> ciphertext = payload.AsSpan(NonceByteLength + TagByteLength);
            byte[] plaintext = new byte[ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, TagByteLength);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
                unprotected = Encoding.UTF8.GetString(plaintext);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            unprotected = string.Empty;
            return false;
        }
    }
}
