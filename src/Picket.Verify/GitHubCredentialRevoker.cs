using Picket.Security;
using System.Globalization;
using System.Net;

namespace Picket.Verify;

/// <summary>
/// Submits explicit, unauthenticated GitHub credential revocation requests.
/// </summary>
/// <param name="options">The GitHub credential revoker options.</param>
public sealed class GitHubCredentialRevoker(GitHubCredentialRevokerOptions options) : IDisposable
{
    private const int MaxCredentialsPerRequest = 1_000;
    private readonly HttpClient _client = CreateHttpClient(options);
    private readonly GitHubCredentialRevokerOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Creates a GitHub credential revoker with default options.
    /// </summary>
    public GitHubCredentialRevoker()
        : this(GitHubCredentialRevokerOptions.CreateDefault())
    {
    }

    /// <summary>
    /// Submits credentials to GitHub's credential revocation API.
    /// </summary>
    /// <param name="credentials">Credentials from the documented GitHub token families.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A non-secret revocation result.</returns>
    public async ValueTask<CredentialRevocationResult> RevokeAsync(
        string[] credentials,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        cancellationToken.ThrowIfCancellationRequested();

        CredentialRevocationResult? inputResult = ValidateInput(credentials);
        if (inputResult is not null)
        {
            return inputResult;
        }

        EndpointGuardResult endpointResult = EndpointGuard.Evaluate(
            _options.CredentialEndpoint,
            _options.EndpointGuardOptions);
        if (!endpointResult.IsAllowed)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                string.Concat("GitHub revocation endpoint was blocked: ", endpointResult.Message),
                credentials.Length);
        }

        try
        {
            using HttpRequestMessage request = CreateRequest(credentials);
            using HttpResponseMessage response = await _client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            return CreateResult(response.StatusCode, credentials.Length);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                "GitHub revocation request timed out; the provider outcome is unknown",
                credentials.Length);
        }
        catch (HttpRequestException)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                "GitHub revocation request failed; the provider outcome is unknown",
                credentials.Length);
        }
    }

    /// <summary>
    /// Releases the underlying HTTP client and handler.
    /// </summary>
    public void Dispose()
    {
        _client.Dispose();
    }

    private HttpRequestMessage CreateRequest(string[] credentials)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _options.CredentialEndpoint)
        {
            Content = new GitHubCredentialRevocationContent(credentials),
        };
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        if (_options.ApiVersion.Length != 0)
        {
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", _options.ApiVersion);
        }

        return request;
    }

    private static CredentialRevocationResult CreateResult(HttpStatusCode statusCode, int credentialCount)
    {
        int numericStatusCode = (int)statusCode;
        return statusCode switch
        {
            HttpStatusCode.Accepted => new CredentialRevocationResult(
                CredentialRevocationState.Accepted,
                "GitHub accepted the credential revocation request",
                credentialCount,
                numericStatusCode),
            HttpStatusCode.UnprocessableEntity => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                "GitHub rejected the credential revocation request",
                credentialCount,
                numericStatusCode),
            HttpStatusCode.Forbidden => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                "GitHub refused the unauthenticated credential revocation request",
                credentialCount,
                numericStatusCode),
            (HttpStatusCode)429 => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                "GitHub rate limited the credential revocation request",
                credentialCount,
                numericStatusCode),
            >= HttpStatusCode.MultipleChoices and < HttpStatusCode.BadRequest => new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                "GitHub returned a redirect that Picket did not follow",
                credentialCount,
                numericStatusCode),
            >= HttpStatusCode.BadRequest and < HttpStatusCode.InternalServerError => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                string.Concat("GitHub rejected the credential revocation request with HTTP ", numericStatusCode.ToString(CultureInfo.InvariantCulture)),
                credentialCount,
                numericStatusCode),
            _ => new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                string.Concat("GitHub returned HTTP ", numericStatusCode.ToString(CultureInfo.InvariantCulture), "; the provider outcome is unknown"),
                credentialCount,
                numericStatusCode),
        };
    }

    private static CredentialRevocationResult? ValidateInput(string[] credentials)
    {
        if (credentials.Length == 0)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                "GitHub revocation requires at least one credential",
                0);
        }

        if (credentials.Length > MaxCredentialsPerRequest)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                "GitHub accepts at most 1000 credentials per revocation request",
                credentials.Length);
        }

        for (int i = 0; i < credentials.Length; i++)
        {
            if (credentials[i] is null || !GitHubCredentialSyntax.IsRevocable(credentials[i]))
            {
                return new CredentialRevocationResult(
                    CredentialRevocationState.Blocked,
                    string.Concat("Credential ", (i + 1).ToString(CultureInfo.InvariantCulture), " is not a supported GitHub token type"),
                    credentials.Length);
            }
        }

        return null;
    }

    private static HttpClient CreateHttpClient(GitHubCredentialRevokerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.CreateHttpClient();
    }
}
