using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Picket.Engine;

namespace Picket.Verify;

/// <summary>
/// Verifies GitHub token findings by calling the GitHub REST API.
/// </summary>
/// <param name="options">The GitHub validator options.</param>
public sealed class GitHubSecretLiveValidator(GitHubSecretLiveValidatorOptions? options = null) : ISecretLiveValidator, IDisposable
{
    private const string VersionValue = "github-rest-user-v1";
    private readonly GitHubSecretLiveValidatorOptions _options = options ?? GitHubSecretLiveValidatorOptions.CreateDefault();
    private readonly HttpClient _client = (options ?? GitHubSecretLiveValidatorOptions.CreateDefault()).CreateHttpClient();

    /// <summary>
    /// Gets the provider identifier used for cache keys and audit records.
    /// </summary>
    public string Provider => "github";

    /// <summary>
    /// Gets the validator version or configuration fingerprint used for cache invalidation.
    /// </summary>
    public string Version => VersionValue;

    /// <summary>
    /// Gets the provider endpoint contacted by this validator.
    /// </summary>
    public Uri Endpoint => _options.UserEndpoint;

    /// <summary>
    /// Returns a value indicating whether this validator can verify the finding.
    /// </summary>
    /// <param name="finding">The finding to evaluate.</param>
    /// <returns><see langword="true" /> when the finding is a supported GitHub token rule; otherwise <see langword="false" />.</returns>
    public bool Supports(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string secret = finding.Secret.Length == 0 ? finding.Match : finding.Secret;
        return finding.RuleID switch
        {
            "github-app-token" => IsClassicGitHubToken(secret, "ghu_") || IsClassicGitHubToken(secret, "ghs_"),
            "github-fine-grained-pat" => IsFineGrainedGitHubToken(secret),
            "github-oauth" => IsClassicGitHubToken(secret, "gho_"),
            "github-pat" => IsClassicGitHubToken(secret, "ghp_"),
            "github-refresh-token" => IsClassicGitHubToken(secret, "ghr_"),
            "picket-github-app-token" => IsClassicGitHubToken(secret, "ghu_") || IsClassicGitHubToken(secret, "ghs_"),
            "picket-github-fine-grained-personal-access-token" => IsFineGrainedGitHubToken(secret),
            "picket-github-oauth-token" => IsClassicGitHubToken(secret, "gho_"),
            "picket-github-personal-access-token" => IsClassicGitHubToken(secret, "ghp_"),
            "picket-github-refresh-token" => IsClassicGitHubToken(secret, "ghr_"),
            _ => false,
        };
    }

    /// <summary>
    /// Verifies the finding by contacting the GitHub REST API.
    /// </summary>
    /// <param name="finding">The finding to verify.</param>
    /// <param name="cancellationToken">A token that can cancel the provider request.</param>
    /// <returns>The live validation result.</returns>
    public async ValueTask<SecretValidationResult> VerifyAsync(Finding finding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        cancellationToken.ThrowIfCancellationRequested();

        string secret = finding.Secret.Length == 0 ? finding.Match : finding.Secret;
        if (secret.Length == 0)
        {
            return new SecretValidationResult(SecretValidationState.Skipped, "finding has no secret material to verify");
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, _options.UserEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        if (_options.ApiVersion.Length != 0)
        {
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", _options.ApiVersion);
        }

        try
        {
            using HttpResponseMessage response = await _client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            await DrainSmallResponseAsync(response, cancellationToken).ConfigureAwait(false);
            return response.StatusCode switch
            {
                HttpStatusCode.OK => new SecretValidationResult(SecretValidationState.Active, "GitHub accepted the token"),
                HttpStatusCode.Unauthorized => new SecretValidationResult(SecretValidationState.Inactive, "GitHub rejected the token"),
                HttpStatusCode.Forbidden => new SecretValidationResult(SecretValidationState.Error, "GitHub forbade the verification request"),
                (HttpStatusCode)429 => new SecretValidationResult(SecretValidationState.Error, "GitHub rate limited the verification request"),
                _ => new SecretValidationResult(SecretValidationState.Error, string.Concat("GitHub returned HTTP ", ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture))),
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new SecretValidationResult(SecretValidationState.Error, "GitHub verification timed out");
        }
        catch (HttpRequestException)
        {
            return new SecretValidationResult(SecretValidationState.Error, "GitHub verification request failed");
        }
    }

    /// <summary>
    /// Releases the underlying HTTP client and handler.
    /// </summary>
    public void Dispose()
    {
        _client.Dispose();
    }

    private async ValueTask DrainSmallResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content is null)
        {
            return;
        }

        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[Math.Min(_options.MaxResponseBytes, 4096)];
        int remaining = _options.MaxResponseBytes;
        while (remaining > 0)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }

            remaining -= read;
        }
    }

    private static bool IsClassicGitHubToken(string secret, string prefix)
    {
        if (secret.Length != 40 || !secret.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        for (int i = prefix.Length; i < secret.Length; i++)
        {
            if (!IsAsciiAlphaNumeric(secret[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsFineGrainedGitHubToken(string secret)
    {
        const string Prefix = "github_pat_";
        if (secret.Length != Prefix.Length + 82 || !secret.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        for (int i = Prefix.Length; i < secret.Length; i++)
        {
            char value = secret[i];
            if (!IsAsciiAlphaNumeric(value) && value != '_')
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
