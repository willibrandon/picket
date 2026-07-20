using System.Text;

namespace Picket.Engine;

/// <summary>
/// Produces credential spans from parsed npm configuration assignments.
/// </summary>
internal static class NativeNpmCredentialDetector
{
    private const int MaxCredentialLength = 64 * 1024;
    private static readonly string[] s_basicDecodePath = ["npm-basic-base64"];
    private static readonly string[] s_passwordDecodePath = ["npm-password-base64"];
    private static readonly string[] s_tags = ["structured:npmrc"];

    internal static List<NativeDetectorMatch> Find(string ruleId, NativeNpmrcIndex index)
    {
        bool tokenRule = ruleId.Contains("auth-token", StringComparison.Ordinal);
        var matches = new List<NativeDetectorMatch>();
        foreach (NativeNpmrcProperty property in index.Properties)
        {
            if (tokenRule)
            {
                if (property.Name.Equals("_authToken", StringComparison.OrdinalIgnoreCase)
                    && IsPlausibleToken(property.Value))
                {
                    matches.Add(CreateMatch(property, property.Value, decodePath: null));
                }

                continue;
            }

            if (property.Name.Equals("_auth", StringComparison.OrdinalIgnoreCase)
                && TryDecodeBase64(property.Value, requireBasicSeparator: true, out string credential))
            {
                matches.Add(CreateMatch(property, credential, s_basicDecodePath));
                continue;
            }

            if (property.Name.Equals("_password", StringComparison.OrdinalIgnoreCase)
                && index.HasUsername(property.Scope)
                && TryDecodeBase64(property.Value, requireBasicSeparator: false, out string password))
            {
                matches.Add(CreateMatch(property, password, s_passwordDecodePath));
            }
        }

        return matches;
    }

    private static NativeDetectorMatch CreateMatch(
        NativeNpmrcProperty property,
        string secret,
        IReadOnlyList<string>? decodePath)
    {
        return new NativeDetectorMatch(
            property.ValueStart,
            property.ValueEnd,
            property.ValueStart,
            property.ValueEnd,
            secret,
            secret,
            s_tags,
            decodePath);
    }

    private static bool TryDecodeBase64(string value, bool requireBasicSeparator, out string credential)
    {
        if (value.Length is < 4 or > MaxCredentialLength)
        {
            credential = string.Empty;
            return false;
        }

        byte[] bytes = new byte[checked((value.Length * 3 / 4) + 3)];
        if (!Convert.TryFromBase64String(value, bytes, out int bytesWritten))
        {
            credential = string.Empty;
            return false;
        }

        try
        {
            credential = new UTF8Encoding(false, true).GetString(bytes, 0, bytesWritten);
        }
        catch (DecoderFallbackException)
        {
            credential = string.Empty;
            return false;
        }

        if (!IsPrintable(credential))
        {
            return false;
        }

        if (!requireBasicSeparator)
        {
            return credential.Length != 0;
        }

        int separator = credential.IndexOf(':');
        return separator > 0 && separator < credential.Length - 1;
    }

    private static bool IsPlausibleToken(string value)
    {
        if (value.Length is < 8 or > MaxCredentialLength
            || value.StartsWith("${", StringComparison.Ordinal))
        {
            return false;
        }

        return IsPrintable(value) && !value.Contains(' ');
    }

    private static bool IsPrintable(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsControl(value[i]))
            {
                return false;
            }
        }

        return true;
    }
}
