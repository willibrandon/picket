using System.Net;
using Picket.Engine;
using Picket.Verify;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitHubSecretLiveValidator" />.
/// </summary>
[TestClass]
public sealed class GitHubSecretLiveValidatorTests
{
    /// <summary>
    /// Verifies that successful GitHub responses produce active validation results and use bearer auth.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReturnsActiveForOkResponse()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"login\":\"octocat\"}"),
        });
        GitHubSecretLiveValidator validator = CreateValidator(handler);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Active, result.State);
        Assert.AreEqual(1, handler.RequestCount);
        Assert.IsNotNull(handler.LastRequest);
        Assert.AreEqual("Bearer", handler.LastRequest.Headers.Authorization?.Scheme);
        Assert.AreEqual(CreateGitHubPat(), handler.LastRequest.Headers.Authorization?.Parameter);
        Assert.Contains("picket", handler.LastRequest.Headers.UserAgent.ToString());
    }

    /// <summary>
    /// Verifies that rejected GitHub credentials produce inactive validation results.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReturnsInactiveForUnauthorizedResponse()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        GitHubSecretLiveValidator validator = CreateValidator(handler);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Inactive, result.State);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that malformed GitHub-looking findings are not eligible for provider requests.
    /// </summary>
    [TestMethod]
    public void SupportsRejectsMalformedGitHubTokens()
    {
        GitHubSecretLiveValidator validator = CreateValidator(new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));

        bool supported = validator.Supports(CreateFinding("ghp_invalid"));

        Assert.IsFalse(supported);
    }

    /// <summary>
    /// Verifies that endpoint overrides cannot include query strings.
    /// </summary>
    [TestMethod]
    public void UserEndpointRejectsQueryString()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(() => options.UserEndpoint = new Uri("https://api.github.test/user?token=value"));
    }

    private static GitHubSecretLiveValidator CreateValidator(FakeHttpMessageHandler handler)
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        options.UserEndpoint = new Uri("https://api.github.test/user");
        options.SetMessageHandlerFactory(() => handler);
        return new GitHubSecretLiveValidator(options);
    }

    private static Finding CreateFinding(string? secret = null)
    {
        secret ??= CreateGitHubPat();
        return new Finding(
            "github-pat",
            "GitHub token",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:github-pat:1");
    }

    private static string CreateGitHubPat()
    {
        return string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
}
