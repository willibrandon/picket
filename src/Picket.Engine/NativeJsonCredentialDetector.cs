using Picket.Rules;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Produces credential spans from a shared streaming JSON index.
/// </summary>
internal static class NativeJsonCredentialDetector
{
    private const int MaxAssignmentValueLength = 16 * 1024;
    private static readonly string[] s_dockerDecodePath = ["docker-auth-base64"];
    private static readonly string[] s_jsonDecodePath = ["json-string"];
    private static readonly string[] s_jsonTags = ["structured:json"];

    internal static List<NativeDetectorMatch> Find(
        SecretRule rule,
        NativeJsonIndex? index,
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        return rule.Detector switch
        {
            PicketBuiltInDetectorNames.CodexCredentials => FindCodex(rule, index, input, isCancellationRequested),
            PicketBuiltInDetectorNames.DockerRegistryCredentials when index is not null => FindDocker(index),
            PicketBuiltInDetectorNames.GcpServiceAccountKey when index is not null => FindGcpServiceAccountKeys(index),
            PicketBuiltInDetectorNames.JwkPrivateKey when index is not null => FindJwkPrivateKeys(index),
            PicketBuiltInDetectorNames.McpServerCredentials when index is not null => FindMcpServerCredentials(index),
            _ => [],
        };
    }

    private static List<NativeDetectorMatch> FindCodex(
        SecretRule rule,
        NativeJsonIndex? index,
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        bool refreshToken = rule.Id.Contains("refresh", StringComparison.Ordinal);
        string propertyName = refreshToken ? "refresh_token" : "access_token";
        var matches = new List<NativeDetectorMatch>();
        if (index is not null)
        {
            foreach (NativeJsonStringProperty property in index.Properties)
            {
                if (IsCancellationRequested(isCancellationRequested))
                {
                    return matches;
                }

                if (property.Name.Equals(propertyName, StringComparison.Ordinal)
                    && ContainsPathSegment(property.Path, "tokens")
                    && IsPlausibleCodexToken(property.Value, refreshToken))
                {
                    matches.Add(CreateJsonMatch(property));
                }
            }
        }

        AddCodexAssignments(matches, input, propertyName, refreshToken, isCancellationRequested);
        return matches;
    }

    private static List<NativeDetectorMatch> FindDocker(NativeJsonIndex index)
    {
        var matches = new List<NativeDetectorMatch>();
        foreach (NativeJsonStringProperty property in index.Properties)
        {
            if (!property.Name.Equals("auth", StringComparison.Ordinal)
                || !ContainsPathSegment(property.Path, "auths")
                || !TryDecodeBasicCredential(property.Value, out string credential))
            {
                continue;
            }

            matches.Add(new NativeDetectorMatch(
                property.ValueStart,
                property.ValueEnd,
                property.ValueStart,
                property.ValueEnd,
                credential,
                credential,
                s_jsonTags,
                s_dockerDecodePath));
        }

        return matches;
    }

    private static List<NativeDetectorMatch> FindGcpServiceAccountKeys(NativeJsonIndex index)
    {
        var matches = new List<NativeDetectorMatch>();
        foreach (NativeJsonStringProperty property in index.Properties)
        {
            if (!property.Name.Equals("private_key", StringComparison.Ordinal)
                || !property.Value.Contains("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal)
                || !index.HasObjectProperty(property.ObjectId, "type", "service_account")
                || !index.HasObjectProperty(property.ObjectId, "client_email"))
            {
                continue;
            }

            matches.Add(CreateJsonMatch(property));
        }

        return matches;
    }

    private static List<NativeDetectorMatch> FindJwkPrivateKeys(NativeJsonIndex index)
    {
        var matches = new List<NativeDetectorMatch>();
        foreach (NativeJsonStringProperty property in index.Properties)
        {
            if (!property.Name.Equals("d", StringComparison.Ordinal)
                || property.Value.Length < 32
                || !IsBase64Url(property.Value))
            {
                continue;
            }

            bool rsa = index.HasObjectProperty(property.ObjectId, "kty", "RSA")
                && index.HasObjectProperty(property.ObjectId, "n")
                && index.HasObjectProperty(property.ObjectId, "e");
            bool ellipticCurve = (index.HasObjectProperty(property.ObjectId, "kty", "EC")
                    || index.HasObjectProperty(property.ObjectId, "kty", "OKP"))
                && index.HasObjectProperty(property.ObjectId, "crv")
                && index.HasObjectProperty(property.ObjectId, "x");
            if (rsa || ellipticCurve)
            {
                matches.Add(CreateJsonMatch(property));
            }
        }

        return matches;
    }

    private static List<NativeDetectorMatch> FindMcpServerCredentials(NativeJsonIndex index)
    {
        var matches = new List<NativeDetectorMatch>();
        foreach (NativeJsonStringProperty property in index.Properties)
        {
            if (!IsMcpServerEnvironmentProperty(property)
                || !IsCredentialEnvironmentVariableName(property.Name)
                || !IsPlausibleMcpCredential(property.Value))
            {
                continue;
            }

            matches.Add(CreateJsonMatch(property));
        }

        return matches;
    }

    private static NativeDetectorMatch CreateJsonMatch(NativeJsonStringProperty property)
    {
        return new NativeDetectorMatch(
            property.ValueStart,
            property.ValueEnd,
            property.ValueStart,
            property.ValueEnd,
            property.Value,
            property.Value,
            s_jsonTags,
            property.ValueIsEscaped ? s_jsonDecodePath : null);
    }

    private static void AddCodexAssignments(
        List<NativeDetectorMatch> matches,
        ReadOnlySpan<byte> input,
        string propertyName,
        bool refreshToken,
        Func<bool>? isCancellationRequested)
    {
        byte[] label = Encoding.UTF8.GetBytes(propertyName);
        int searchOffset = 0;
        while (searchOffset < input.Length)
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            int relativeLabelStart = input[searchOffset..].IndexOf(label);
            if (relativeLabelStart < 0)
            {
                return;
            }

            int labelStart = searchOffset + relativeLabelStart;
            int afterLabel = labelStart + label.Length;
            if (IsIdentifierBoundary(input, labelStart - 1)
                && IsIdentifierBoundary(input, afterLabel)
                && TryReadAssignmentValue(input, afterLabel, out int valueStart, out int valueEnd))
            {
                string value = Encoding.UTF8.GetString(input[valueStart..valueEnd]);
                if (IsPlausibleCodexToken(value, refreshToken) && !ContainsMatch(matches, valueStart, valueEnd))
                {
                    matches.Add(new NativeDetectorMatch(
                        valueStart,
                        valueEnd,
                        valueStart,
                        valueEnd,
                        value,
                        value,
                        s_jsonTags));
                }
            }

            searchOffset = afterLabel;
        }
    }

    private static bool TryReadAssignmentValue(
        ReadOnlySpan<byte> input,
        int offset,
        out int valueStart,
        out int valueEnd)
    {
        int delimiterLimit = Math.Min(input.Length, offset + 32);
        while (offset < delimiterLimit && IsAssignmentPadding(input[offset]))
        {
            offset++;
        }

        if (offset >= delimiterLimit || input[offset] is not ((byte)'=' or (byte)':'))
        {
            valueStart = 0;
            valueEnd = 0;
            return false;
        }

        offset++;
        while (offset < input.Length && IsHorizontalWhitespace(input[offset]))
        {
            offset++;
        }

        byte quote = 0;
        if (offset < input.Length && input[offset] is (byte)'\'' or (byte)'"')
        {
            quote = input[offset++];
        }

        valueStart = offset;
        int limit = Math.Min(input.Length, valueStart + MaxAssignmentValueLength);
        while (offset < limit && !IsAssignmentTerminator(input[offset], quote))
        {
            offset++;
        }

        valueEnd = offset;
        return valueEnd > valueStart;
    }

    private static bool TryDecodeBasicCredential(string value, out string credential)
    {
        if (value.Length is < 8 or > MaxAssignmentValueLength)
        {
            credential = string.Empty;
            return false;
        }

        int maxLength = checked((value.Length * 3 / 4) + 3);
        byte[] bytes = new byte[maxLength];
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

        int separator = credential.IndexOf(':');
        return separator > 0 && separator < credential.Length - 1 && IsPrintable(credential);
    }

    private static bool IsPlausibleCodexToken(string value, bool refreshToken)
    {
        if (value.Length is < 32 or > MaxAssignmentValueLength || !IsPrintable(value))
        {
            return false;
        }

        return refreshToken
            ? value.Contains('_') || value.Length >= 48
            : value.StartsWith("eyJ", StringComparison.Ordinal) && value.Count(static character => character == '.') == 2;
    }

    private static bool ContainsMatch(List<NativeDetectorMatch> matches, int start, int end)
    {
        for (int i = 0; i < matches.Count; i++)
        {
            if (matches[i].MatchStart == start && matches[i].MatchEnd == end)
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsPathSegment(string[] path, string value)
    {
        for (int i = 0; i < path.Length; i++)
        {
            if (path[i].Equals(value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsBase64Url(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char character = value[i];
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsMcpServerEnvironmentProperty(NativeJsonStringProperty property)
    {
        string[] path = property.Path;
        return path.Length == 4
            && path[0].Equals("mcpServers", StringComparison.Ordinal)
            && path[1].Length != 0
            && path[2].Equals("env", StringComparison.Ordinal)
            && path[3].Equals(property.Name, StringComparison.Ordinal);
    }

    private static bool IsCredentialEnvironmentVariableName(string name)
    {
        return EndsWithNameSegment(name, "AUTH")
            || EndsWithNameSegment(name, "COOKIE")
            || EndsWithNameSegment(name, "CREDENTIAL")
            || EndsWithNameSegment(name, "CREDENTIALS")
            || EndsWithNameSegment(name, "KEY") && !ContainsNameSegment(name, "PUBLIC")
            || EndsWithNameSegment(name, "PASSPHRASE")
            || EndsWithNameSegment(name, "PASSWD")
            || EndsWithNameSegment(name, "PASSWORD")
            || EndsWithNameSegment(name, "PAT")
            || EndsWithNameSegment(name, "SECRET")
            || EndsWithNameSegment(name, "SESSION")
            || EndsWithNameSegment(name, "TOKEN");
    }

    private static bool IsPlausibleMcpCredential(string value)
    {
        return value.Length is >= 8 and <= MaxAssignmentValueLength
            && IsPrintable(value)
            && !IsEnvironmentReference(value);
    }

    private static bool IsEnvironmentReference(string value)
    {
        ReadOnlySpan<char> candidate = value.AsSpan().Trim();
        if (candidate.Length < 3)
        {
            return false;
        }

        if (candidate[0] == '$')
        {
            ReadOnlySpan<char> name = candidate[1] == '{' && candidate[^1] == '}'
                ? candidate[2..^1]
                : candidate[1..];
            return IsEnvironmentVariableName(name);
        }

        return candidate[0] == '%'
            && candidate[^1] == '%'
            && IsEnvironmentVariableName(candidate[1..^1]);
    }

    private static bool IsEnvironmentVariableName(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || !IsEnvironmentVariableStart(value[0]))
        {
            return false;
        }

        for (int i = 1; i < value.Length; i++)
        {
            if (!IsEnvironmentVariableCharacter(value[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool EndsWithNameSegment(string name, string segment)
    {
        if (!name.EndsWith(segment, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int segmentStart = name.Length - segment.Length;
        return segmentStart == 0 || !char.IsAsciiLetterOrDigit(name[segmentStart - 1]);
    }

    private static bool ContainsNameSegment(string name, string segment)
    {
        int searchOffset = 0;
        while (searchOffset <= name.Length - segment.Length)
        {
            int relativeStart = name.AsSpan(searchOffset).IndexOf(segment, StringComparison.OrdinalIgnoreCase);
            if (relativeStart < 0)
            {
                return false;
            }

            int start = searchOffset + relativeStart;
            int end = start + segment.Length;
            if ((start == 0 || !char.IsAsciiLetterOrDigit(name[start - 1]))
                && (end == name.Length || !char.IsAsciiLetterOrDigit(name[end])))
            {
                return true;
            }

            searchOffset = start + 1;
        }

        return false;
    }

    private static bool IsEnvironmentVariableStart(char value)
    {
        return char.IsAsciiLetter(value) || value == '_';
    }

    private static bool IsEnvironmentVariableCharacter(char value)
    {
        return IsEnvironmentVariableStart(value) || char.IsAsciiDigit(value);
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

    private static bool IsIdentifierBoundary(ReadOnlySpan<byte> input, int offset)
    {
        if ((uint)offset >= (uint)input.Length)
        {
            return true;
        }

        byte value = input[offset];
        return value is not (>= (byte)'A' and <= (byte)'Z')
            and not (>= (byte)'a' and <= (byte)'z')
            and not (>= (byte)'0' and <= (byte)'9')
            and not (byte)'_';
    }

    private static bool IsAssignmentPadding(byte value)
    {
        return value is (byte)' ' or (byte)'\t' or (byte)'\'' or (byte)'"';
    }

    private static bool IsHorizontalWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t';
    }

    private static bool IsAssignmentTerminator(byte value, byte quote)
    {
        return quote == 0
            ? value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',' or (byte)';'
            : value == quote || value is (byte)'\r' or (byte)'\n';
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }
}
