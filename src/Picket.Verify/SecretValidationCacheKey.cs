using System.Security.Cryptography;
using System.Text;
using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Identifies one live validation cache entry without storing raw secret material.
/// </summary>
public sealed class SecretValidationCacheKey
{
    private const string LowerHex = "0123456789abcdef";

    private SecretValidationCacheKey(string provider, string validatorVersion, string ruleId, string secretSha256, string endpoint)
    {
        Provider = provider;
        ValidatorVersion = validatorVersion;
        RuleId = ruleId;
        SecretSha256 = secretSha256;
        Endpoint = endpoint;
        Fingerprint = ComputeSha256Hex(string.Concat(provider, "\n", validatorVersion, "\n", ruleId, "\n", secretSha256, "\n", endpoint));
    }

    /// <summary>
    /// Gets the provider identifier.
    /// </summary>
    public string Provider { get; }

    /// <summary>
    /// Gets the provider validator version.
    /// </summary>
    public string ValidatorVersion { get; }

    /// <summary>
    /// Gets the finding rule identifier.
    /// </summary>
    public string RuleId { get; }

    /// <summary>
    /// Gets the lowercase SHA-256 hash of the secret.
    /// </summary>
    public string SecretSha256 { get; }

    /// <summary>
    /// Gets the normalized provider endpoint without query or fragment data.
    /// </summary>
    public string Endpoint { get; }

    /// <summary>
    /// Gets the stable SHA-256 cache-key fingerprint.
    /// </summary>
    public string Fingerprint { get; }

    /// <summary>
    /// Creates a validation cache key from non-secret components.
    /// </summary>
    /// <param name="provider">The provider identifier.</param>
    /// <param name="validatorVersion">The provider validator version.</param>
    /// <param name="ruleId">The finding rule identifier.</param>
    /// <param name="secretSha256">The lowercase or uppercase SHA-256 hash of the secret.</param>
    /// <param name="endpoint">The provider endpoint.</param>
    /// <returns>The validation cache key.</returns>
    public static SecretValidationCacheKey Create(
        string provider,
        string validatorVersion,
        string ruleId,
        string secretSha256,
        Uri endpoint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(validatorVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ArgumentNullException.ThrowIfNull(endpoint);

        return new SecretValidationCacheKey(
            provider,
            validatorVersion,
            ruleId,
            NormalizeSecretHash(secretSha256),
            NormalizeEndpoint(endpoint));
    }

    /// <summary>
    /// Creates a validation cache key from a finding.
    /// </summary>
    /// <param name="provider">The provider identifier.</param>
    /// <param name="validatorVersion">The provider validator version.</param>
    /// <param name="finding">The finding to key.</param>
    /// <param name="endpoint">The provider endpoint.</param>
    /// <returns>The validation cache key.</returns>
    public static SecretValidationCacheKey FromFinding(string provider, string validatorVersion, Finding finding, Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string secretSha256 = finding.SecretSha256.Length == 0
            ? ComputeSecretSha256(finding)
            : finding.SecretSha256;
        return Create(provider, validatorVersion, finding.RuleID, secretSha256, endpoint);
    }

    private static string NormalizeEndpoint(Uri endpoint)
    {
        if (!endpoint.IsAbsoluteUri)
        {
            throw new ArgumentException("Endpoint URI must be absolute.", nameof(endpoint));
        }

        return endpoint.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
    }

    private static string NormalizeSecretHash(string secretSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretSha256);
        if (secretSha256.Length != 64)
        {
            throw new ArgumentException("Secret hash must be a SHA-256 hex string.", nameof(secretSha256));
        }

        var builder = new StringBuilder(64);
        for (int i = 0; i < secretSha256.Length; i++)
        {
            char value = secretSha256[i];
            if (value is >= '0' and <= '9' or >= 'a' and <= 'f')
            {
                builder.Append(value);
                continue;
            }

            if (value is >= 'A' and <= 'F')
            {
                builder.Append((char)(value + 32));
                continue;
            }

            throw new ArgumentException("Secret hash must be a SHA-256 hex string.", nameof(secretSha256));
        }

        return builder.ToString();
    }

    private static string ComputeSecretSha256(Finding finding)
    {
        string secret = finding.Secret.Length == 0 ? finding.Match : finding.Secret;
        return ComputeSha256Hex(secret);
    }

    private static string ComputeSha256Hex(string value)
    {
        return ComputeSha256Hex(Encoding.UTF8.GetBytes(value));
    }

    private static string ComputeSha256Hex(ReadOnlySpan<byte> content)
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
