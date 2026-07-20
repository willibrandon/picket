namespace Picket.Verify;

/// <summary>
/// Recognizes credential families accepted by GitHub verification and revocation APIs.
/// </summary>
internal static class GitHubCredentialSyntax
{
    private const int MaxCredentialLength = 4 * 1_024;

    /// <summary>
    /// Returns whether a value has a supported GitHub App user or installation token shape.
    /// </summary>
    /// <param name="credential">The credential value.</param>
    /// <returns><see langword="true" /> when the credential has a supported GitHub App token shape.</returns>
    internal static bool IsAppToken(string credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        if (credential.Length > MaxCredentialLength)
        {
            return false;
        }

        if (credential.Length == 40
            && (credential.StartsWith("ghu_", StringComparison.Ordinal)
                || credential.StartsWith("ghs_", StringComparison.Ordinal)))
        {
            return HasSuffix(credential, 4, allowUnderscore: false);
        }

        const string InstallationPrefix = "ghs_";
        if (!credential.StartsWith(InstallationPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        int separator = credential.IndexOf('_', InstallationPrefix.Length);
        if ((separator <= InstallationPrefix.Length || separator > InstallationPrefix.Length + 20)
            || separator == credential.Length - 1)
        {
            return false;
        }

        for (int i = InstallationPrefix.Length; i < separator; i++)
        {
            if (credential[i] is < '0' or > '9')
            {
                return false;
            }
        }

        return HasJwtShape(credential.AsSpan(separator + 1));
    }

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

        if (IsAppToken(credential))
        {
            return true;
        }

        return (credential.StartsWith("ghp_", StringComparison.Ordinal)
                || credential.StartsWith("gho_", StringComparison.Ordinal)
                || credential.StartsWith("ghr_", StringComparison.Ordinal))
            && HasSuffix(credential, 4, allowUnderscore: false);
    }

    private static bool HasJwtShape(ReadOnlySpan<char> value)
    {
        int firstSeparator = value.IndexOf('.');
        if (firstSeparator is < 8 or > 256)
        {
            return false;
        }

        int secondSeparatorRelative = value[(firstSeparator + 1)..].IndexOf('.');
        if (secondSeparatorRelative < 8)
        {
            return false;
        }

        int secondSeparator = firstSeparator + 1 + secondSeparatorRelative;
        if (secondSeparatorRelative > 1_024
            || value.Length - secondSeparator - 1 is < 8 or > 1_024)
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char character = value[i];
            if (character != '.' && !IsAsciiAlphaNumeric(character) && character is not '_' and not '-')
            {
                return false;
            }
        }

        return value[(secondSeparator + 1)..].IndexOf('.') < 0;
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
