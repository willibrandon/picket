using Picket.Verify;
using System.Net;
using System.Text.Json;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitHubCredentialRevoker" />.
/// </summary>
[TestClass]
public sealed class GitHubCredentialRevokerTests
{
    /// <summary>
    /// Gets or sets the current MSTest context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the documented unauthenticated request shape and accepted result.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncPostsUnauthenticatedCredentialList()
    {
        string firstCredential = CreateCredential("ghp_", 36);
        string secondCredential = CreateCredential("ghr_", 76);
        string requestBody = string.Empty;
        var handler = new FakeHttpMessageHandler(request =>
        {
            Assert.AreEqual(HttpMethod.Post, request.Method);
            Assert.AreEqual(new Uri("https://8.8.8.8/credentials/revoke"), request.RequestUri);
            Assert.IsNull(request.Headers.Authorization);
            Assert.Contains("application/vnd.github+json", request.Headers.Accept.ToString());
            Assert.Contains("picket", request.Headers.UserAgent.ToString());
            Assert.Contains("2026-03-10", request.Headers.GetValues("X-GitHub-Api-Version"));
            requestBody = request.Content!.ReadAsStringAsync(TestContext.CancellationToken).GetAwaiter().GetResult();
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        });
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [firstCredential, secondCredential],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Accepted, result.State);
        Assert.AreEqual(202, result.HttpStatusCode);
        Assert.AreEqual(2, result.CredentialCount);
        Assert.DoesNotContain(firstCredential, result.Reason);
        Assert.DoesNotContain(secondCredential, result.Reason);
        Assert.AreEqual(1, handler.RequestCount);
        using JsonDocument document = JsonDocument.Parse(requestBody);
        JsonElement credentials = document.RootElement.GetProperty("credentials");
        Assert.AreEqual(2, credentials.GetArrayLength());
        Assert.AreEqual(firstCredential, credentials[0].GetString());
        Assert.AreEqual(secondCredential, credentials[1].GetString());
    }

    /// <summary>
    /// Verifies that unrelated values are blocked before an HTTP request is created.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncBlocksUnsupportedCredentialWithoutRequest()
    {
        const string UnsupportedCredential = "not-a-github-token";
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Accepted));
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [UnsupportedCredential],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.DoesNotContain(UnsupportedCredential, result.Reason);
    }

    /// <summary>
    /// Verifies that requests larger than GitHub's documented limit are blocked locally.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncBlocksMoreThanOneThousandCredentialsWithoutRequest()
    {
        string credential = CreateCredential("ghp_", 36);
        string[] credentials = Enumerable.Repeat(credential, 1_001).ToArray();
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Accepted));
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            credentials,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.Contains("1000", result.Reason);
    }

    /// <summary>
    /// Verifies that a non-public endpoint is blocked before a custom handler can observe credentials.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncBlocksNonPublicEndpointBeforeRequest()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Accepted));
        GitHubCredentialRevokerOptions options = CreateOptions(handler);
        options.CredentialEndpoint = new Uri("https://127.0.0.1/credentials/revoke");
        using var revoker = new GitHubCredentialRevoker(options);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [CreateCredential("ghp_", 36)],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.Contains("non-public", result.Reason);
    }

    /// <summary>
    /// Verifies that redirect responses are surfaced without following the target.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncDoesNotFollowRedirectResponse()
    {
        var handler = new FakeHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri("https://metadata.google.internal/latest/meta-data");
            return response;
        });
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [CreateCredential("ghp_", 36)],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(307, result.HttpStatusCode);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains("did not follow", result.Reason);
    }

    /// <summary>
    /// Verifies provider response classification without exposing credential material.
    /// </summary>
    /// <param name="statusCode">The provider status code.</param>
    /// <param name="expectedState">The expected revocation state.</param>
    [TestMethod]
    [DataRow(403, CredentialRevocationState.Rejected)]
    [DataRow(422, CredentialRevocationState.Rejected)]
    [DataRow(429, CredentialRevocationState.Rejected)]
    [DataRow(500, CredentialRevocationState.Indeterminate)]
    public async Task RevokeAsyncClassifiesProviderResponse(int statusCode, CredentialRevocationState expectedState)
    {
        string credential = CreateCredential("ghp_", 36);
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)statusCode));
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [credential],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedState, result.State);
        Assert.AreEqual(statusCode, result.HttpStatusCode);
        Assert.DoesNotContain(credential, result.Reason);
    }

    /// <summary>
    /// Verifies that transport failures preserve an indeterminate outcome without exception details.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncReturnsIndeterminateForTransportFailure()
    {
        string credential = CreateCredential("ghp_", 36);
        var handler = new FakeHttpMessageHandler(_ => throw new HttpRequestException(credential));
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            [credential],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Indeterminate, result.State);
        Assert.DoesNotContain(credential, result.Reason);
    }

    /// <summary>
    /// Verifies that caller cancellation is propagated instead of being reported as a provider outcome.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncPropagatesCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Accepted));
        using GitHubCredentialRevoker revoker = CreateRevoker(handler);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await revoker.RevokeAsync([CreateCredential("ghp_", 36)], cancellation.Token).ConfigureAwait(false));

        Assert.AreEqual(0, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that endpoint overrides reject credential-bearing URI components.
    /// </summary>
    [TestMethod]
    public void CredentialEndpointRejectsUserInfoAndQuery()
    {
        GitHubCredentialRevokerOptions options = GitHubCredentialRevokerOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://user@example.test/credentials/revoke"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://example.test/credentials/revoke?value=secret"));
    }

    private static GitHubCredentialRevoker CreateRevoker(FakeHttpMessageHandler handler)
    {
        return new GitHubCredentialRevoker(CreateOptions(handler));
    }

    private static GitHubCredentialRevokerOptions CreateOptions(FakeHttpMessageHandler handler)
    {
        GitHubCredentialRevokerOptions options = GitHubCredentialRevokerOptions.CreateDefault();
        options.CredentialEndpoint = new Uri("https://8.8.8.8/credentials/revoke");
        options.SetMessageHandlerFactory(() => handler);
        return options;
    }

    private static string CreateCredential(string prefix, int suffixLength)
    {
        return string.Concat(prefix, new string('a', suffixLength));
    }
}
