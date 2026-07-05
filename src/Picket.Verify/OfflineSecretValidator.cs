using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Performs safe offline validation that does not contact providers or exfiltrate secret material.
/// </summary>
public static class OfflineSecretValidator
{
    private static readonly Encoding s_strictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Validates one finding without contacting external services.
    /// </summary>
    /// <param name="finding">The finding to validate.</param>
    /// <returns>The validation result.</returns>
    public static SecretValidationResult Validate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string secret = finding.Secret.Length == 0 ? finding.Match : finding.Secret;
        if (secret.Length == 0)
        {
            return Unknown();
        }

        if (IsTestCredential(secret))
        {
            return new SecretValidationResult(SecretValidationState.TestCredential, "known test or placeholder marker");
        }

        return finding.RuleID switch
        {
            "aws-access-token" => ValidateAwsAccessKeyId(secret),
            "github-app-token" => ValidateGitHubClassicToken(secret, "ghu_", "ghs_"),
            "github-fine-grained-pat" => ValidateGitHubFineGrainedToken(secret),
            "github-oauth" => ValidateGitHubClassicToken(secret, "gho_"),
            "github-pat" => ValidateGitHubClassicToken(secret, "ghp_"),
            "github-refresh-token" => ValidateGitHubClassicToken(secret, "ghr_"),
            "gcp-api-key" => ValidateGcpApiKey(secret),
            "jwt" => ValidateJwt(secret),
            "jwt-base64" => ValidateBase64EncodedJwt(secret),
            "picket-gcp-service-account-key" => ValidateGcpServiceAccountKeyJson(secret),
            "picket-azure-storage-connection-string" => ValidateAzureStorageConnectionString(finding.Match, secret),
            "private-key" => ValidatePrivateKeyEnvelope(finding.Match),
            _ => Unknown(),
        };
    }

    /// <summary>
    /// Returns a finding annotated with an offline validation state.
    /// </summary>
    /// <param name="finding">The finding to annotate.</param>
    /// <returns>The original finding when it is already annotated; otherwise an annotated copy.</returns>
    public static Finding Annotate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (finding.ValidationState.Length != 0
            && !finding.ValidationState.Equals("unknown", StringComparison.Ordinal))
        {
            return finding;
        }

        SecretValidationResult result = Validate(finding);
        if (result.State == SecretValidationState.Unknown && finding.ValidationState.Length != 0)
        {
            return finding;
        }

        return CopyWithValidationState(finding, result.ReportValue);
    }

    /// <summary>
    /// Returns findings annotated with offline validation states.
    /// </summary>
    /// <param name="findings">The findings to annotate.</param>
    /// <returns>A list of annotated findings in the same order.</returns>
    public static List<Finding> AnnotateAll(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var annotated = new List<Finding>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            annotated.Add(Annotate(findings[i]));
        }

        return annotated;
    }

    private static SecretValidationResult ValidateAwsAccessKeyId(string secret)
    {
        if (secret.Length != 20 || !HasAnyPrefix(secret, "AKIA", "ASIA", "ABIA", "ACCA") && !HasA3TPrefix(secret))
        {
            return Invalid("invalid AWS access key ID shape");
        }

        for (int i = 4; i < secret.Length; i++)
        {
            if (!IsAwsAccessKeyIdSuffixCharacter(secret[i]))
            {
                return Invalid("invalid AWS access key ID alphabet");
            }
        }

        return StructurallyValid("valid AWS access key ID shape");
    }

    private static SecretValidationResult ValidateGitHubClassicToken(string secret, params string[] prefixes)
    {
        if (secret.Length != 40 || !HasAnyPrefix(secret, prefixes))
        {
            return Invalid("invalid GitHub token shape");
        }

        return HasAsciiAlphaNumericSuffix(secret, 4)
            ? StructurallyValid("valid GitHub token shape")
            : Invalid("invalid GitHub token alphabet");
    }

    private static SecretValidationResult ValidateGitHubFineGrainedToken(string secret)
    {
        const string Prefix = "github_pat_";
        if (secret.Length != Prefix.Length + 82 || !secret.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return Invalid("invalid GitHub fine-grained token shape");
        }

        for (int i = Prefix.Length; i < secret.Length; i++)
        {
            if (!IsWordCharacter(secret[i]))
            {
                return Invalid("invalid GitHub fine-grained token alphabet");
            }
        }

        return StructurallyValid("valid GitHub fine-grained token shape");
    }

    private static SecretValidationResult ValidatePrivateKeyEnvelope(string match)
    {
        return match.Contains("-----BEGIN", StringComparison.Ordinal)
            && match.Contains("PRIVATE KEY", StringComparison.Ordinal)
            && match.Contains("-----END", StringComparison.Ordinal)
            ? StructurallyValid("valid private key envelope")
            : Invalid("invalid private key envelope");
    }

    private static SecretValidationResult ValidateAzureStorageConnectionString(string match, string secret)
    {
        if (!TryGetConnectionStringField(match, "DefaultEndpointsProtocol", out ReadOnlySpan<char> protocol)
            || !IsAzureStorageProtocol(protocol)
            || !TryGetConnectionStringField(match, "AccountName", out ReadOnlySpan<char> accountName)
            || !IsAzureStorageAccountName(accountName)
            || !TryGetConnectionStringField(match, "AccountKey", out ReadOnlySpan<char> accountKey)
            || !accountKey.SequenceEqual(secret.AsSpan())
            || !IsAzureStorageAccountKey(secret))
        {
            return Invalid("invalid Azure Storage connection string shape");
        }

        if (TryGetConnectionStringField(match, "EndpointSuffix", out ReadOnlySpan<char> endpointSuffix)
            && !IsAzureEndpointSuffix(endpointSuffix))
        {
            return Invalid("invalid Azure Storage endpoint suffix");
        }

        return StructurallyValid("valid Azure Storage connection string shape");
    }

    private static SecretValidationResult ValidateGcpApiKey(string secret)
    {
        const string Prefix = "AIza";
        if (secret.Length != Prefix.Length + 35
            || !secret.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return Invalid("invalid GCP API key shape");
        }

        for (int i = Prefix.Length; i < secret.Length; i++)
        {
            if (!IsGcpApiKeySuffixCharacter(secret[i]))
            {
                return Invalid("invalid GCP API key alphabet");
            }
        }

        return StructurallyValid("valid GCP API key shape");
    }

    private static SecretValidationResult ValidateGcpServiceAccountKeyJson(string secret)
    {
        if (!TryParseJsonObject(secret, out JsonDocument? document))
        {
            return Invalid("invalid GCP service account key JSON");
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (!TryGetJsonString(root, "type", out string type)
                || !type.Equals("service_account", StringComparison.Ordinal)
                || !TryGetJsonString(root, "project_id", out string projectId)
                || !IsGcpProjectId(projectId)
                || !TryGetJsonString(root, "private_key_id", out string privateKeyId)
                || !IsGcpPrivateKeyId(privateKeyId)
                || !TryGetJsonString(root, "private_key", out string privateKey)
                || ValidatePrivateKeyEnvelope(privateKey).State != SecretValidationState.StructurallyValid
                || !TryGetJsonString(root, "client_email", out string clientEmail)
                || !IsGcpServiceAccountEmail(clientEmail, projectId)
                || !TryGetJsonString(root, "token_uri", out string tokenUri)
                || !tokenUri.Equals("https://oauth2.googleapis.com/token", StringComparison.Ordinal))
            {
                return Invalid("invalid GCP service account key shape");
            }
        }

        return StructurallyValid("valid GCP service account key shape");
    }

    private static bool TryParseJsonObject(string json, [NotNullWhen(true)] out JsonDocument? document)
    {
        document = null;
        try
        {
            document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return true;
            }

            document.Dispose();
            document = null;
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryGetJsonString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(propertyName, out JsonElement property)
            || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool IsGcpProjectId(string projectId)
    {
        if (projectId.Length is < 6 or > 30
            || !IsLowerAsciiAlpha(projectId[0])
            || !IsLowerAsciiAlphaNumeric(projectId[^1]))
        {
            return false;
        }

        for (int i = 1; i < projectId.Length - 1; i++)
        {
            char value = projectId[i];
            if (!IsLowerAsciiAlphaNumeric(value) && value != '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsGcpPrivateKeyId(string privateKeyId)
    {
        if (privateKeyId.Length != 40)
        {
            return false;
        }

        for (int i = 0; i < privateKeyId.Length; i++)
        {
            if (!IsLowerHexCharacter(privateKeyId[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsGcpServiceAccountEmail(string clientEmail, string projectId)
    {
        string suffix = string.Concat("@", projectId, ".iam.gserviceaccount.com");
        if (!clientEmail.EndsWith(suffix, StringComparison.Ordinal)
            || clientEmail.Length <= suffix.Length)
        {
            return false;
        }

        ReadOnlySpan<char> name = clientEmail.AsSpan(0, clientEmail.Length - suffix.Length);
        for (int i = 0; i < name.Length; i++)
        {
            char value = name[i];
            if (!IsAsciiAlphaNumeric(value) && value is not '.' and not '_' and not '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsGcpApiKeySuffixCharacter(char value)
    {
        return IsAsciiAlphaNumeric(value) || value is '_' or '-';
    }

    private static bool TryGetConnectionStringField(
        string connectionString,
        string fieldName,
        out ReadOnlySpan<char> fieldValue)
    {
        ReadOnlySpan<char> remaining = connectionString.AsSpan().Trim();
        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOf(';');
            ReadOnlySpan<char> segment = separator < 0 ? remaining : remaining[..separator];
            segment = segment.Trim();
            if (!segment.IsEmpty)
            {
                int equals = segment.IndexOf('=');
                if (equals <= 0)
                {
                    fieldValue = [];
                    return false;
                }

                ReadOnlySpan<char> key = segment[..equals].Trim();
                if (key.Equals(fieldName.AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    fieldValue = segment[(equals + 1)..].Trim();
                    return true;
                }
            }

            if (separator < 0)
            {
                break;
            }

            remaining = remaining[(separator + 1)..];
        }

        fieldValue = [];
        return false;
    }

    private static bool IsAzureStorageProtocol(ReadOnlySpan<char> protocol)
    {
        return protocol.Equals("https".AsSpan(), StringComparison.OrdinalIgnoreCase)
            || protocol.Equals("http".AsSpan(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAzureStorageAccountName(ReadOnlySpan<char> accountName)
    {
        if (accountName.Length is < 3 or > 24)
        {
            return false;
        }

        for (int i = 0; i < accountName.Length; i++)
        {
            if (!IsLowerAsciiAlphaNumeric(accountName[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAzureStorageAccountKey(string secret)
    {
        if (!IsStandardBase64Segment(secret.AsSpan())
            || !TryBase64Decode(secret.AsSpan(), urlSafe: false, out byte[]? bytes))
        {
            return false;
        }

        return bytes.Length == 64;
    }

    private static bool IsAzureEndpointSuffix(ReadOnlySpan<char> endpointSuffix)
    {
        if (endpointSuffix.IsEmpty || endpointSuffix[0] is '.' or '-')
        {
            return false;
        }

        bool hasDot = false;
        char previous = '\0';
        for (int i = 0; i < endpointSuffix.Length; i++)
        {
            char value = endpointSuffix[i];
            if (value == '.')
            {
                if (previous is '\0' or '.' or '-')
                {
                    return false;
                }

                hasDot = true;
            }
            else if (value == '-')
            {
                if (previous is '\0' or '.' or '-')
                {
                    return false;
                }
            }
            else if (!IsAsciiAlphaNumeric(value))
            {
                return false;
            }

            previous = value;
        }

        return hasDot && previous is not '.' and not '-';
    }

    private static SecretValidationResult ValidateBase64EncodedJwt(string secret)
    {
        string normalizedSecret = RemoveAsciiWhitespace(secret);
        if (!TryBase64Decode(normalizedSecret, urlSafe: false, out byte[]? bytes))
        {
            return Invalid("invalid base64 JWT wrapper");
        }

        string decoded = DecodeUtf8(bytes);
        if (decoded.Length == 0)
        {
            return Invalid("invalid base64 JWT wrapper");
        }

        SecretValidationResult result = ValidateJwt(decoded);
        return result.State == SecretValidationState.StructurallyValid
            ? StructurallyValid("valid base64-encoded JWT structure")
            : result;
    }

    private static SecretValidationResult ValidateJwt(string secret)
    {
        ReadOnlySpan<char> token = secret.AsSpan().Trim();
        int firstDot = token.IndexOf('.');
        if (firstDot <= 0)
        {
            return Invalid("invalid JWT segment count");
        }

        ReadOnlySpan<char> remaining = token[(firstDot + 1)..];
        int secondDotOffset = remaining.IndexOf('.');
        if (secondDotOffset <= 0)
        {
            return Invalid("invalid JWT segment count");
        }

        int secondDot = firstDot + 1 + secondDotOffset;
        if (token[(secondDot + 1)..].Contains('.'))
        {
            return Invalid("invalid JWT segment count");
        }

        ReadOnlySpan<char> headerSegment = token[..firstDot];
        ReadOnlySpan<char> payloadSegment = token[(firstDot + 1)..secondDot];
        ReadOnlySpan<char> signatureSegment = token[(secondDot + 1)..];
        if (!TryDecodeJwtSegment(headerSegment, out byte[]? headerBytes)
            || !TryDecodeJwtSegment(payloadSegment, out byte[]? payloadBytes))
        {
            return Invalid("invalid JWT base64url segment");
        }

        if (!TryReadJwtAlgorithm(headerBytes, out string? algorithm))
        {
            return Invalid("invalid JWT header");
        }

        if (!IsSupportedJwtAlgorithm(algorithm))
        {
            return Invalid("invalid JWT algorithm");
        }

        if (!IsJsonObject(payloadBytes))
        {
            return Invalid("invalid JWT payload");
        }

        if (!IsJwtSignatureSegmentValid(signatureSegment))
        {
            return Invalid("invalid JWT signature segment");
        }

        bool unsignedJwt = algorithm.Equals("none", StringComparison.OrdinalIgnoreCase);
        if (unsignedJwt && signatureSegment.Length != 0)
        {
            return Invalid("JWT signature must be empty for alg none");
        }

        if (signatureSegment.Length == 0 && !unsignedJwt)
        {
            return Invalid("JWT signature is missing");
        }

        return StructurallyValid("valid JWT structure");
    }

    private static string RemoveAsciiWhitespace(string value)
    {
        int firstWhitespace = -1;
        for (int i = 0; i < value.Length; i++)
        {
            if (IsAsciiWhitespace(value[i]))
            {
                firstWhitespace = i;
                break;
            }
        }

        if (firstWhitespace < 0)
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        builder.Append(value.AsSpan(0, firstWhitespace));
        for (int i = firstWhitespace + 1; i < value.Length; i++)
        {
            if (!IsAsciiWhitespace(value[i]))
            {
                builder.Append(value[i]);
            }
        }

        return builder.ToString();
    }

    private static bool TryDecodeJwtSegment(ReadOnlySpan<char> segment, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (segment.IsEmpty || !IsBase64UrlSegment(segment))
        {
            return false;
        }

        return TryBase64Decode(segment, urlSafe: true, out bytes);
    }

    private static bool TryBase64Decode(ReadOnlySpan<char> encoded, bool urlSafe, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (encoded.Length == 0)
        {
            return false;
        }

        string normalized = NormalizeBase64(encoded, urlSafe);
        try
        {
            bytes = Convert.FromBase64String(normalized);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string NormalizeBase64(ReadOnlySpan<char> encoded, bool urlSafe)
    {
        var builder = new StringBuilder(encoded.Length + 3);
        for (int i = 0; i < encoded.Length; i++)
        {
            char value = encoded[i];
            builder.Append(urlSafe
                ? value switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => value,
                }
                : value);
        }

        int padding = builder.Length % 4;
        if (padding != 0)
        {
            builder.Append('=', 4 - padding);
        }

        return builder.ToString();
    }

    private static string DecodeUtf8(byte[] bytes)
    {
        try
        {
            return s_strictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return string.Empty;
        }
    }

    private static bool TryReadJwtAlgorithm(byte[] headerBytes, [NotNullWhen(true)] out string? algorithm)
    {
        algorithm = null;
        var reader = new Utf8JsonReader(headerBytes);
        if (!TryReadJsonToken(ref reader) || reader.TokenType != JsonTokenType.StartObject)
        {
            return false;
        }

        while (TryReadJsonToken(ref reader))
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return !string.IsNullOrWhiteSpace(algorithm)
                    && HasNoTrailingJsonToken(ref reader);
            }

            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                return false;
            }

            bool isAlgorithmProperty = reader.ValueTextEquals("alg"u8);
            if (!TryReadJsonToken(ref reader))
            {
                return false;
            }

            if (isAlgorithmProperty)
            {
                if (reader.TokenType != JsonTokenType.String)
                {
                    return false;
                }

                algorithm = reader.GetString();
                continue;
            }

            if (!TrySkipJsonValue(ref reader))
            {
                return false;
            }
        }

        return false;
    }

    private static bool IsJsonObject(byte[] bytes)
    {
        var reader = new Utf8JsonReader(bytes);
        return TryReadJsonToken(ref reader)
            && reader.TokenType == JsonTokenType.StartObject
            && TrySkipJsonValue(ref reader)
            && HasNoTrailingJsonToken(ref reader);
    }

    private static bool TryReadJsonToken(ref Utf8JsonReader reader)
    {
        try
        {
            return reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TrySkipJsonValue(ref Utf8JsonReader reader)
    {
        try
        {
            reader.Skip();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasNoTrailingJsonToken(ref Utf8JsonReader reader)
    {
        try
        {
            return !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsSupportedJwtAlgorithm(string algorithm)
    {
        return algorithm.Equals("none", StringComparison.OrdinalIgnoreCase)
            || algorithm.Equals("EdDSA", StringComparison.Ordinal)
            || IsJwtAlgorithmFamily(algorithm, "HS")
            || IsJwtAlgorithmFamily(algorithm, "RS")
            || IsJwtAlgorithmFamily(algorithm, "ES")
            || IsJwtAlgorithmFamily(algorithm, "PS");
    }

    private static bool IsJwtAlgorithmFamily(string algorithm, string prefix)
    {
        return algorithm.StartsWith(prefix, StringComparison.Ordinal)
            && algorithm.Length > prefix.Length;
    }

    private static bool IsJwtSignatureSegmentValid(ReadOnlySpan<char> segment)
    {
        if (segment.IsEmpty)
        {
            return true;
        }

        return IsBase64UrlSegment(segment);
    }

    private static bool IsBase64UrlSegment(ReadOnlySpan<char> segment)
    {
        bool paddingStarted = false;
        for (int i = 0; i < segment.Length; i++)
        {
            char value = segment[i];
            if (value == '=')
            {
                paddingStarted = true;
                continue;
            }

            if (paddingStarted || !IsBase64UrlCharacter(value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsStandardBase64Segment(ReadOnlySpan<char> segment)
    {
        if (segment.IsEmpty)
        {
            return false;
        }

        bool paddingStarted = false;
        for (int i = 0; i < segment.Length; i++)
        {
            char value = segment[i];
            if (value == '=')
            {
                paddingStarted = true;
                continue;
            }

            if (paddingStarted || !IsStandardBase64Character(value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBase64UrlCharacter(char value)
    {
        return IsAsciiAlphaNumeric(value) || value is '-' or '_';
    }

    private static bool IsStandardBase64Character(char value)
    {
        return IsAsciiAlphaNumeric(value) || value is '+' or '/';
    }

    private static bool IsAsciiWhitespace(char value)
    {
        return value is ' ' or '\t' or '\r' or '\n';
    }

    private static Finding CopyWithValidationState(Finding finding, string validationState)
    {
        return new Finding(
            finding.RuleID,
            finding.Description,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            finding.File,
            finding.SymlinkFile,
            finding.Commit,
            finding.Entropy,
            finding.Author,
            finding.Email,
            finding.Date,
            finding.Message,
            finding.Tags,
            finding.Fingerprint,
            finding.Line,
            finding.Link,
            finding.SecretSha256,
            finding.MatchSha256,
            validationState,
            finding.BlobSha256,
            finding.DecodePath);
    }

    private static bool IsTestCredential(string secret)
    {
        return secret.Contains("example", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("dummy", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("fake", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("placeholder", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("changeme", StringComparison.OrdinalIgnoreCase)
            || secret.Contains("changeit", StringComparison.OrdinalIgnoreCase)
            || HasRepeatedSingleCharacter(secret);
    }

    private static bool HasRepeatedSingleCharacter(string secret)
    {
        if (secret.Length < 8)
        {
            return false;
        }

        char first = secret[0];
        for (int i = 1; i < secret.Length; i++)
        {
            if (secret[i] != first)
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasAnyPrefix(string secret, params string[] prefixes)
    {
        for (int i = 0; i < prefixes.Length; i++)
        {
            if (secret.StartsWith(prefixes[i], StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasA3TPrefix(string secret)
    {
        return secret.StartsWith("A3T", StringComparison.Ordinal)
            && secret.Length >= 4
            && IsAsciiAlphaNumeric(secret[3]);
    }

    private static bool IsAwsAccessKeyIdSuffixCharacter(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= '2' and <= '7';
    }

    private static bool HasAsciiAlphaNumericSuffix(string secret, int start)
    {
        for (int i = start; i < secret.Length; i++)
        {
            if (!IsAsciiAlphaNumeric(secret[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsWordCharacter(char value)
    {
        return IsAsciiAlphaNumeric(value) || value == '_';
    }

    private static bool IsLowerAsciiAlphaNumeric(char value)
    {
        return value is >= 'a' and <= 'z'
            or >= '0' and <= '9';
    }

    private static bool IsLowerAsciiAlpha(char value)
    {
        return value is >= 'a' and <= 'z';
    }

    private static bool IsLowerHexCharacter(char value)
    {
        return value is >= '0' and <= '9'
            or >= 'a' and <= 'f';
    }

    private static bool IsAsciiAlphaNumeric(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9';
    }

    private static SecretValidationResult Unknown()
    {
        return new SecretValidationResult(SecretValidationState.Unknown);
    }

    private static SecretValidationResult StructurallyValid(string reason)
    {
        return new SecretValidationResult(SecretValidationState.StructurallyValid, reason);
    }

    private static SecretValidationResult Invalid(string reason)
    {
        return new SecretValidationResult(SecretValidationState.Invalid, reason);
    }
}
