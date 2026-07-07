using Picket.Engine;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

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

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using HttpRequestMessage request = CreateRequest(secret);
                using HttpResponseMessage response = await _client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);

                string responseBody = await ReadSmallResponseAsync(response, cancellationToken).ConfigureAwait(false);
                if (IsRetryableStatusCode(response.StatusCode) && CanRetry(attempt))
                {
                    await DelayBeforeRetryAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                return AddRetryEvidence(CreateResult(response, responseBody), attempt);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                if (CanRetry(attempt))
                {
                    await DelayBeforeRetryAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                return AddRetryEvidence(CreateTransientErrorResult("GitHub verification timed out"), attempt);
            }
            catch (HttpRequestException)
            {
                if (CanRetry(attempt))
                {
                    await DelayBeforeRetryAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                return AddRetryEvidence(CreateTransientErrorResult("GitHub verification request failed"), attempt);
            }
        }
    }

    /// <summary>
    /// Releases the underlying HTTP client and handler.
    /// </summary>
    public void Dispose()
    {
        _client.Dispose();
    }

    private HttpRequestMessage CreateRequest(string secret)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, _options.UserEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        if (_options.ApiVersion.Length != 0)
        {
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", _options.ApiVersion);
        }

        return request;
    }

    private SecretValidationResult CreateResult(HttpResponseMessage response, string responseBody)
    {
        return response.StatusCode switch
        {
            HttpStatusCode.OK => CreateActiveResult(response, responseBody),
            HttpStatusCode.Unauthorized => CreateHttpResult(SecretValidationState.Inactive, "GitHub rejected the token", response.StatusCode),
            HttpStatusCode.Forbidden => CreateHttpResult(SecretValidationState.Error, "GitHub forbade the verification request", response.StatusCode),
            (HttpStatusCode)429 => CreateHttpResult(SecretValidationState.Error, "GitHub rate limited the verification request", response.StatusCode),
            _ => CreateHttpResult(
                SecretValidationState.Error,
                string.Concat("GitHub returned HTTP ", ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture)),
                response.StatusCode),
        };
    }

    private SecretValidationResult CreateActiveResult(HttpResponseMessage response, string responseBody)
    {
        string identity = TryReadGitHubLogin(responseBody, out string login) ? login : string.Empty;
        string[] scopes = ReadCommaSeparatedHeaders(response, "X-OAuth-Scopes");
        var evidence = new List<string>
        {
            "provider=github",
            string.Concat("endpoint=", _options.UserEndpoint.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped)),
            "httpStatus=200"
        };
        if (identity.Length != 0)
        {
            evidence.Add(string.Concat("githubLogin=", identity));
        }

        if (scopes.Length != 0)
        {
            evidence.Add(string.Concat("scopeCount=", scopes.Length.ToString(CultureInfo.InvariantCulture)));
        }

        return new SecretValidationResult(
            SecretValidationState.Active,
            "GitHub accepted the token",
            identity,
            scopes,
            ["github:user"],
            [.. evidence]);
    }

    private static SecretValidationResult CreateHttpResult(SecretValidationState state, string reason, HttpStatusCode statusCode)
    {
        return new SecretValidationResult(
            state,
            reason,
            evidence: [string.Concat("httpStatus=", ((int)statusCode).ToString(CultureInfo.InvariantCulture))],
            isPersistentCacheable: state != SecretValidationState.Error);
    }

    private static SecretValidationResult CreateTransientErrorResult(string reason)
    {
        return new SecretValidationResult(
            SecretValidationState.Error,
            reason,
            evidence: ["errorKind=transient"],
            isPersistentCacheable: false);
    }

    private static SecretValidationResult AddRetryEvidence(SecretValidationResult result, int retryAttempts)
    {
        if (retryAttempts == 0)
        {
            return result;
        }

        var evidence = new List<string>(result.Evidence.Count + 1);
        for (int i = 0; i < result.Evidence.Count; i++)
        {
            evidence.Add(result.Evidence[i]);
        }

        evidence.Add(string.Concat("retryAttempts=", retryAttempts.ToString(CultureInfo.InvariantCulture)));
        return new SecretValidationResult(
            result.State,
            result.Reason,
            result.Identity,
            Copy(result.Scopes),
            Copy(result.ReachableResources),
            [.. evidence],
            result.IsPersistentCacheable);
    }

    private bool CanRetry(int attempt)
    {
        return attempt < _options.MaxRetryAttempts;
    }

    private async ValueTask DelayBeforeRetryAsync(CancellationToken cancellationToken)
    {
        if (_options.RetryDelay == TimeSpan.Zero)
        {
            return;
        }

        await Task.Delay(_options.RetryDelay, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsRetryableStatusCode(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.RequestTimeout
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
    }

    private static string[] Copy(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return [];
        }

        var copy = new string[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            copy[i] = values[i];
        }

        return copy;
    }

    private async ValueTask<string> ReadSmallResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content is null)
        {
            return string.Empty;
        }

        using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[Math.Min(_options.MaxResponseBytes, 4096)];
        int remaining = _options.MaxResponseBytes;
        using var output = new MemoryStream(Math.Min(_options.MaxResponseBytes, 4096));
        while (remaining > 0)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
            remaining -= read;
        }

        return Encoding.UTF8.GetString(output.ToArray());
    }

    private static bool TryReadGitHubLogin(string responseBody, out string login)
    {
        login = string.Empty;
        if (responseBody.Length == 0)
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseBody);
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("login", out JsonElement loginProperty)
                || loginProperty.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            login = loginProperty.GetString() ?? string.Empty;
            return login.Length != 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string[] ReadCommaSeparatedHeaders(HttpResponseMessage response, string headerName)
    {
        if (!response.Headers.TryGetValues(headerName, out IEnumerable<string>? values))
        {
            return [];
        }

        var parsed = new List<string>();
        foreach (string value in values)
        {
            string[] fields = value.Split(',');
            for (int i = 0; i < fields.Length; i++)
            {
                string field = fields[i].Trim();
                if (field.Length != 0)
                {
                    parsed.Add(field);
                }
            }
        }

        return [.. parsed];
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
