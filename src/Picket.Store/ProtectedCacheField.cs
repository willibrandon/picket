using System.Text;

namespace Picket.Store;

internal static class ProtectedCacheField
{
    private static readonly byte[] s_keyDerivationPurpose = Encoding.UTF8.GetBytes("picket.scan-cache.field-protection.v1");

    internal static byte[] DeriveKey(ReadOnlySpan<byte> authenticationKey)
    {
        return ProtectedStatePayload.DeriveKey(authenticationKey, s_keyDerivationPurpose);
    }

    internal static string Protect(ReadOnlySpan<byte> key, string value)
    {
        return ProtectedStatePayload.Protect(key, value);
    }

    internal static bool TryUnprotect(ReadOnlySpan<byte> key, string value, out string unprotected)
    {
        return ProtectedStatePayload.TryUnprotect(key, value, out unprotected);
    }
}
