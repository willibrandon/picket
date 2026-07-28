using Picket.Security;
using System.Globalization;
using System.Net;

namespace Picket.Verify;

/// <summary>
/// Explicitly self-revokes a GitLab personal access token.
/// </summary>
/// <param name="options">The GitLab personal access token revoker options.</param>
public sealed class GitLabPersonalAccessTokenRevoker(GitLabPersonalAccessTokenRevokerOptions options) : IDisposable
{
    private const int MaxCredentialLength = 4_096;
    private readonly HttpClient _client = CreateHttpClient(options);
    private readonly GitLabPersonalAccessTokenRevokerOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Creates a GitLab personal access token revoker with default options.
    /// </summary>
    public GitLabPersonalAccessTokenRevoker()
        : this(GitLabPersonalAccessTokenRevokerOptions.CreateDefault())
    {
    }

    /// <summary>
    /// Self-revokes a GitLab personal access token.
    /// </summary>
    /// <param name="credential">The GitLab personal access token.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>A non-secret revocation result.</returns>
    public async ValueTask<CredentialRevocationResult> RevokeAsync(
        string credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsValidCredential(credential))
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                "Credential is not a valid GitLab personal access token value",
                1);
        }

        EndpointGuardResult endpointResult = EndpointGuard.Evaluate(
            _options.CredentialEndpoint,
            _options.EndpointGuardOptions);
        if (!endpointResult.IsAllowed)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                string.Concat("GitLab revocation endpoint was blocked: ", endpointResult.Message),
                1);
        }

        try
        {
            using HttpRequestMessage request = CreateRequest(credential);
            using HttpResponseMessage response = await _client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            return CreateResult(response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                "GitLab revocation request timed out; the provider outcome is unknown",
                1);
        }
        catch (HttpRequestException)
        {
            return new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                "GitLab revocation request failed; the provider outcome is unknown",
                1);
        }
    }

    /// <summary>
    /// Releases the underlying HTTP client and handler.
    /// </summary>
    public void Dispose()
    {
        _client.Dispose();
    }

    private HttpRequestMessage CreateRequest(string credential)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, _options.CredentialEndpoint);
        request.Headers.Add("PRIVATE-TOKEN", credential);
        request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        return request;
    }

    private static CredentialRevocationResult CreateResult(HttpStatusCode statusCode)
    {
        int numericStatusCode = (int)statusCode;
        return statusCode switch
        {
            HttpStatusCode.NoContent => new CredentialRevocationResult(
                CredentialRevocationState.Accepted,
                "GitLab revoked the personal access token",
                1,
                numericStatusCode),
            HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                "GitLab rejected the personal access token revocation request",
                1,
                numericStatusCode),
            (HttpStatusCode)429 => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                "GitLab rate limited the personal access token revocation request",
                1,
                numericStatusCode),
            >= HttpStatusCode.MultipleChoices and < HttpStatusCode.BadRequest => new CredentialRevocationResult(
                CredentialRevocationState.Blocked,
                "GitLab returned a redirect that Picket did not follow",
                1,
                numericStatusCode),
            >= HttpStatusCode.BadRequest and < HttpStatusCode.InternalServerError => new CredentialRevocationResult(
                CredentialRevocationState.Rejected,
                string.Concat("GitLab rejected the personal access token revocation request with HTTP ", numericStatusCode.ToString(CultureInfo.InvariantCulture)),
                1,
                numericStatusCode),
            _ => new CredentialRevocationResult(
                CredentialRevocationState.Indeterminate,
                string.Concat("GitLab returned HTTP ", numericStatusCode.ToString(CultureInfo.InvariantCulture), "; the provider outcome is unknown"),
                1,
                numericStatusCode),
        };
    }

    private static bool IsValidCredential(string credential)
    {
        if (credential.Length is 0 or > MaxCredentialLength)
        {
            return false;
        }

        for (int i = 0; i < credential.Length; i++)
        {
            if (credential[i] is < '!' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    private static HttpClient CreateHttpClient(GitLabPersonalAccessTokenRevokerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.CreateHttpClient();
    }
}
