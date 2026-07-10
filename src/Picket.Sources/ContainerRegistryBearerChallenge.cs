using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Represents a bounded bearer-token challenge returned by an OCI registry.
/// </summary>
internal sealed class ContainerRegistryBearerChallenge(Uri realm, string service)
{
    internal Uri Realm { get; } = realm;

    internal string Service { get; } = service;

    internal static bool TryCreate(
        HttpResponseMessage response,
        [NotNullWhen(true)] out ContainerRegistryBearerChallenge? challenge)
    {
        challenge = null;
        foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
        {
            if (!header.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(header.Parameter)
                || !TryParseParameters(header.Parameter, out string realmValue, out string service))
            {
                continue;
            }

            if (!Uri.TryCreate(realmValue, UriKind.Absolute, out Uri? realm)
                || realm.Scheme is not "https" and not "http"
                || !string.IsNullOrEmpty(realm.UserInfo)
                || !string.IsNullOrEmpty(realm.Fragment))
            {
                continue;
            }

            challenge = new ContainerRegistryBearerChallenge(realm, service);
            return true;
        }

        return false;
    }

    private static bool TryParseParameters(
        string value,
        out string realm,
        out string service)
    {
        realm = string.Empty;
        service = string.Empty;
        if (value.Length > 4096)
        {
            return false;
        }

        ReadOnlySpan<char> remaining = value;
        while (true)
        {
            remaining = TrimParameterSeparators(remaining);
            if (remaining.IsEmpty)
            {
                break;
            }

            int equalsIndex = remaining.IndexOf('=');
            if (equalsIndex <= 0)
            {
                return false;
            }

            string name = remaining[..equalsIndex].Trim().ToString();
            remaining = remaining[(equalsIndex + 1)..].TrimStart();
            if (!TryReadParameterValue(remaining, out string parameterValue, out int consumed))
            {
                return false;
            }

            remaining = remaining[consumed..];
            if (name.Equals("realm", StringComparison.OrdinalIgnoreCase))
            {
                if (realm.Length != 0)
                {
                    return false;
                }

                realm = parameterValue;
            }
            else if (name.Equals("service", StringComparison.OrdinalIgnoreCase))
            {
                if (service.Length != 0)
                {
                    return false;
                }

                service = parameterValue;
            }
        }

        return realm.Length != 0 && realm.Length <= 2048 && service.Length <= 512;
    }

    private static ReadOnlySpan<char> TrimParameterSeparators(ReadOnlySpan<char> value)
    {
        int index = 0;
        while (index < value.Length && (value[index] == ',' || char.IsWhiteSpace(value[index])))
        {
            index++;
        }

        return value[index..];
    }

    private static bool TryReadParameterValue(
        ReadOnlySpan<char> value,
        out string parameterValue,
        out int consumed)
    {
        parameterValue = string.Empty;
        consumed = 0;
        if (value.IsEmpty)
        {
            return false;
        }

        if (value[0] != '"')
        {
            int separator = value.IndexOf(',');
            ReadOnlySpan<char> token = separator < 0 ? value : value[..separator];
            parameterValue = token.Trim().ToString();
            consumed = separator < 0 ? value.Length : separator;
            return parameterValue.Length != 0 && !ContainsControlCharacter(parameterValue);
        }

        var builder = new StringBuilder();
        bool escaped = false;
        for (int i = 1; i < value.Length; i++)
        {
            char character = value[i];
            if (escaped)
            {
                builder.Append(character);
                escaped = false;
                continue;
            }

            if (character == '\\')
            {
                escaped = true;
                continue;
            }

            if (character == '"')
            {
                parameterValue = builder.ToString();
                consumed = i + 1;
                return parameterValue.Length != 0 && !ContainsControlCharacter(parameterValue);
            }

            builder.Append(character);
            if (builder.Length > 2048)
            {
                return false;
            }
        }

        return false;
    }

    private static bool ContainsControlCharacter(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsControl(value[i]))
            {
                return true;
            }
        }

        return false;
    }
}
