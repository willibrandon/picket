namespace Picket.Verify;

/// <summary>
/// Recognizes credential families accepted by GitHub's credential revocation API.
/// </summary>
internal static class GitHubCredentialSyntax
{
    private const int MaxCredentialLength = 1_024;

    /// <summary>
    /// Returns whether a value has a documented revocable GitHub credential prefix and alphabet.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <returns><see langword="true" /> when the credential has a supported shape.</returns>
    internal static bool IsRevocable(string credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        if (credential.Length > MaxCredentialLength)
        {
            return false;
        }

        if (credential.StartsWith("github_pat_", StringComparison.Ordinal))
        {
            return HasSuffix(credential, "github_pat_".Length, allowUnderscore: true);
        }

        return credential.StartsWith("ghp_", StringComparison.Ordinal)
                || credential.StartsWith("gho_", StringComparison.Ordinal)
                || credential.StartsWith("ghu_", StringComparison.Ordinal)
                || credential.StartsWith("ghr_", StringComparison.Ordinal)
            ? HasSuffix(credential, 4, allowUnderscore: false)
            : false;
    }

    private static bool HasSuffix(string credential, int prefixLength, bool allowUnderscore)
    {
        if (credential.Length == prefixLength)
        {
            return false;
        }

        for (int i = prefixLength; i < credential.Length; i++)
        {
            char value = credential[i];
            if (!IsAsciiAlphaNumeric(value) && (!allowUnderscore || value != '_'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiAlphaNumeric(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9';
    }
}
