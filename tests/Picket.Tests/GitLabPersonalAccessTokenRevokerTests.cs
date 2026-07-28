using Picket.Verify;
using System.Net;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitLabPersonalAccessTokenRevoker" />.
/// </summary>
[TestClass]
public sealed class GitLabPersonalAccessTokenRevokerTests
{
    private const string Credential = "glpat-0123456789abcdefghij";

    /// <summary>
    /// Gets or sets the current MSTest context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the documented authenticated self-revocation request and accepted result.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncDeletesSelfWithPrivateTokenHeader()
    {
        var handler = new FakeHttpMessageHandler(request =>
        {
            Assert.AreEqual(HttpMethod.Delete, request.Method);
            Assert.AreEqual(new Uri("https://8.8.8.8/api/v4/personal_access_tokens/self"), request.RequestUri);
            Assert.IsNull(request.Content);
            Assert.IsNull(request.Headers.Authorization);
            Assert.Contains("picket", request.Headers.UserAgent.ToString());
            Assert.Contains(Credential, request.Headers.GetValues("PRIVATE-TOKEN"));
            Assert.DoesNotContain(Credential, request.RequestUri!.AbsoluteUri);
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Accepted, result.State);
        Assert.AreEqual(204, result.HttpStatusCode);
        Assert.AreEqual(1, result.CredentialCount);
        Assert.DoesNotContain(Credential, result.Reason);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that malformed header values are blocked before an HTTP request is created.
    /// </summary>
    /// <param name="credential">The malformed credential.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("contains whitespace")]
    [DataRow("contains\r\nnewline")]
    public async Task RevokeAsyncBlocksMalformedCredentialWithoutRequest(string credential)
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.AreEqual("Credential is not a valid GitLab personal access token value", result.Reason);
    }

    /// <summary>
    /// Verifies that excessively long credentials are blocked locally.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncBlocksExcessivelyLongCredentialWithoutRequest()
    {
        string credential = new('a', 4_097);
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.DoesNotContain(credential, result.Reason);
    }

    /// <summary>
    /// Verifies that the upper credential-length boundary remains accepted.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncAcceptsMaximumLengthCredential()
    {
        string credential = new('a', 4_096);
        var handler = new FakeHttpMessageHandler(request =>
        {
            Assert.Contains(credential, request.Headers.GetValues("PRIVATE-TOKEN"));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Accepted, result.State);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that GitLab Self-Managed custom token prefixes are accepted.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncAcceptsCustomTokenPrefix()
    {
        const string CustomCredential = "company_pat_0123456789abcdefghij";
        var handler = new FakeHttpMessageHandler(request =>
        {
            Assert.Contains(CustomCredential, request.Headers.GetValues("PRIVATE-TOKEN"));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            CustomCredential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Accepted, result.State);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.DoesNotContain(CustomCredential, result.Reason);
    }

    /// <summary>
    /// Verifies that a non-public endpoint is blocked before a custom handler can observe the token.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncBlocksNonPublicEndpointBeforeRequest()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        GitLabPersonalAccessTokenRevokerOptions options = CreateOptions(handler);
        options.CredentialEndpoint = new Uri("https://127.0.0.1/api/v4/personal_access_tokens/self");
        using var revoker = new GitLabPersonalAccessTokenRevoker(options);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(0, handler.RequestCount);
        Assert.Contains("non-public", result.Reason);
        Assert.DoesNotContain(Credential, result.Reason);
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
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Blocked, result.State);
        Assert.AreEqual(307, result.HttpStatusCode);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains("did not follow", result.Reason);
        Assert.DoesNotContain(Credential, result.Reason);
    }

    /// <summary>
    /// Verifies provider response classification without exposing token material.
    /// </summary>
    /// <param name="statusCode">The provider status code.</param>
    /// <param name="expectedState">The expected revocation state.</param>
    [TestMethod]
    [DataRow(200, CredentialRevocationState.Indeterminate)]
    [DataRow(400, CredentialRevocationState.Rejected)]
    [DataRow(401, CredentialRevocationState.Rejected)]
    [DataRow(403, CredentialRevocationState.Rejected)]
    [DataRow(404, CredentialRevocationState.Rejected)]
    [DataRow(429, CredentialRevocationState.Rejected)]
    [DataRow(500, CredentialRevocationState.Indeterminate)]
    public async Task RevokeAsyncClassifiesProviderResponse(int statusCode, CredentialRevocationState expectedState)
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)statusCode));
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedState, result.State);
        Assert.AreEqual(statusCode, result.HttpStatusCode);
        Assert.DoesNotContain(Credential, result.Reason);
    }

    /// <summary>
    /// Verifies that transport failures preserve an indeterminate outcome without exception details.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncReturnsIndeterminateForTransportFailure()
    {
        var handler = new FakeHttpMessageHandler(_ => throw new HttpRequestException(Credential));
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Indeterminate, result.State);
        Assert.DoesNotContain(Credential, result.Reason);
    }

    /// <summary>
    /// Verifies that the configured request timeout produces an indeterminate provider outcome.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task RevokeAsyncReturnsIndeterminateWhenRequestTimesOut()
    {
        var handler = new CancellableHttpMessageHandler();
        GitLabPersonalAccessTokenRevokerOptions options = GitLabPersonalAccessTokenRevokerOptions.CreateDefault();
        options.CredentialEndpoint = new Uri("https://8.8.8.8/api/v4/personal_access_tokens/self");
        options.Timeout = TimeSpan.FromMilliseconds(25);
        options.SetMessageHandlerFactory(() => handler);
        using var revoker = new GitLabPersonalAccessTokenRevoker(options);

        CredentialRevocationResult result = await revoker.RevokeAsync(
            Credential,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialRevocationState.Indeterminate, result.State);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.Contains("timed out", result.Reason);
        Assert.DoesNotContain(Credential, result.Reason);
    }

    /// <summary>
    /// Verifies that caller cancellation is propagated instead of being reported as a provider outcome.
    /// </summary>
    [TestMethod]
    public async Task RevokeAsyncPropagatesCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        using GitLabPersonalAccessTokenRevoker revoker = CreateRevoker(handler);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await revoker.RevokeAsync(Credential, cancellation.Token).ConfigureAwait(false));

        Assert.AreEqual(0, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that endpoint overrides preserve the self-revocation path and credential transport policy.
    /// </summary>
    [TestMethod]
    public void CredentialEndpointRejectsUnsafeComponentsAndUnrelatedPaths()
    {
        GitLabPersonalAccessTokenRevokerOptions options = GitLabPersonalAccessTokenRevokerOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("http://gitlab.example.test/api/v4/personal_access_tokens/self"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://user@gitlab.example.test/api/v4/personal_access_tokens/self"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://gitlab.example.test/api/v4/personal_access_tokens/self?value=secret"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://gitlab.example.test/api/v4/personal_access_tokens/self#fragment"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.CredentialEndpoint = new Uri("https://gitlab.example.test/api/v4/projects/1"));

        options.CredentialEndpoint = new Uri("https://gitlab.example.test/gitlab/api/v4/personal_access_tokens/self");
        Assert.AreEqual(
            new Uri("https://gitlab.example.test/gitlab/api/v4/personal_access_tokens/self"),
            options.CredentialEndpoint);
    }

    /// <summary>
    /// Verifies that proxy overrides require credential-free HTTPS URIs.
    /// </summary>
    [TestMethod]
    public void ProxyEndpointRejectsInsecureAndCredentialBearingUri()
    {
        GitLabPersonalAccessTokenRevokerOptions options = GitLabPersonalAccessTokenRevokerOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(
            () => options.ProxyEndpoint = new Uri("http://proxy.example.test/"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.ProxyEndpoint = new Uri("https://user@proxy.example.test/"));
        Assert.ThrowsExactly<ArgumentException>(
            () => options.ProxyEndpoint = new Uri("https://proxy.example.test/?value=secret"));
    }

    private static GitLabPersonalAccessTokenRevoker CreateRevoker(FakeHttpMessageHandler handler)
    {
        return new GitLabPersonalAccessTokenRevoker(CreateOptions(handler));
    }

    private static GitLabPersonalAccessTokenRevokerOptions CreateOptions(FakeHttpMessageHandler handler)
    {
        GitLabPersonalAccessTokenRevokerOptions options = GitLabPersonalAccessTokenRevokerOptions.CreateDefault();
        options.CredentialEndpoint = new Uri("https://8.8.8.8/api/v4/personal_access_tokens/self");
        options.SetMessageHandlerFactory(() => handler);
        return options;
    }
}
