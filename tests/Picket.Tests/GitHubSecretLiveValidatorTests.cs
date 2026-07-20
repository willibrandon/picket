using Picket.Engine;
using Picket.Verify;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Authentication;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitHubSecretLiveValidator" />.
/// </summary>
[TestClass]
public sealed class GitHubSecretLiveValidatorTests
{
    /// <summary>
    /// Gets or sets the current MSTest context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that successful GitHub responses produce active validation results and use bearer auth.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReturnsActiveForOkResponse()
    {
        var handler = new FakeHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"login\":\"octocat\"}"),
            };
            response.Headers.Add("X-OAuth-Scopes", "repo, gist");
            return response;
        });
        GitHubSecretLiveValidator validator = CreateValidator(handler);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Active, result.State);
        Assert.AreEqual("octocat", result.Identity);
        Assert.Contains("repo", result.Scopes);
        Assert.Contains("gist", result.Scopes);
        Assert.Contains("github:user", result.ReachableResources);
        Assert.Contains("githubLogin=octocat", result.Evidence);
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
        Assert.Contains("httpStatus=401", result.Evidence);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that redirect responses are treated as provider errors instead of accepted validation.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReturnsErrorForRedirectResponse()
    {
        var handler = new FakeHttpMessageHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("https://metadata.google.internal/latest/meta-data");
            return response;
        });
        GitHubSecretLiveValidator validator = CreateValidator(handler);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("HTTP 302", result.Reason);
        Assert.Contains("httpStatus=302", result.Evidence);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that GitHub rate-limit responses produce auditable error results.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncReturnsErrorForRateLimitedResponse()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)429));
        GitHubSecretLiveValidator validator = CreateValidator(handler);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("rate limited", result.Reason);
        Assert.Contains("httpStatus=429", result.Evidence);
        Assert.AreEqual(1, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that transient GitHub responses are retried before producing an active result.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncRetriesTransientServerResponse()
    {
        int requestCount = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            requestCount++;
            if (requestCount == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"login\":\"octocat\"}"),
            };
        });
        GitHubSecretLiveValidator validator = CreateValidator(handler, options => options.RetryDelay = TimeSpan.Zero);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Active, result.State);
        Assert.AreEqual("octocat", result.Identity);
        Assert.Contains("retryAttempts=1", result.Evidence);
        Assert.IsTrue(result.IsPersistentCacheable);
        Assert.AreEqual(2, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that exhausted transient failures are not persistent-cacheable.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncDoesNotPersistentCacheExhaustedTransientFailure()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        GitHubSecretLiveValidator validator = CreateValidator(handler, options => options.RetryDelay = TimeSpan.Zero);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), CancellationToken.None);

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("httpStatus=503", result.Evidence);
        Assert.Contains("retryAttempts=1", result.Evidence);
        Assert.IsFalse(result.IsPersistentCacheable);
        Assert.AreEqual(2, handler.RequestCount);
    }

    /// <summary>
    /// Verifies that a response body that stalls after headers is bounded even when no caller timeout is provided.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task VerifyAsyncResponseBodyStallsReturnsErrorWithinBound()
    {
        var handler = new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new StallingReadStream()),
        });
        GitHubSecretLiveValidator validator = CreateValidator(
            handler,
            options =>
            {
                options.MaxRetryAttempts = 0;
                options.ResponseBodyReadTimeout = TimeSpan.FromMilliseconds(100);
            });
        Stopwatch stopwatch = Stopwatch.StartNew();

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), TestContext.CancellationToken);

        stopwatch.Stop();
        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("timed out", result.Reason);
        Assert.IsFalse(result.IsPersistentCacheable);
        Assert.IsLessThan(2_000, stopwatch.ElapsedMilliseconds);
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
    /// Verifies that native GitHub token rule IDs are eligible for guarded live verification.
    /// </summary>
    [TestMethod]
    public void SupportsRecognizesNativeGitHubTokens()
    {
        GitHubSecretLiveValidator validator = CreateValidator(new FakeHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        (string RuleId, string Secret)[] cases = [
            ("picket-github-app-token", CreateGitHubClassicToken("ghu_")),
            ("picket-github-app-token", CreateGitHubStatelessInstallationToken()),
            ("picket-github-fine-grained-personal-access-token", CreateGitHubFineGrainedPat()),
            ("picket-github-oauth-token", CreateGitHubClassicToken("gho_")),
            ("picket-github-personal-access-token", CreateGitHubPat()),
            ("picket-github-refresh-token", CreateGitHubClassicToken("ghr_")),
        ];

        for (int i = 0; i < cases.Length; i++)
        {
            Assert.IsTrue(validator.Supports(CreateFinding(cases[i].Secret, cases[i].RuleId)));
        }
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

    /// <summary>
    /// Verifies that endpoint overrides cannot include URI user information.
    /// </summary>
    [TestMethod]
    public void UserEndpointRejectsUserInfo()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(() => options.UserEndpoint = new Uri("https://user:password@api.github.test/user"));
    }

    /// <summary>
    /// Verifies that proxy endpoints cannot carry credential-like URI components.
    /// </summary>
    [TestMethod]
    public void ProxyEndpointRejectsUserInfo()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(() => options.ProxyEndpoint = new Uri("https://user:password@proxy.example.test:8080"));
    }

    /// <summary>
    /// Verifies that plaintext HTTP proxies are rejected by default.
    /// </summary>
    [TestMethod]
    public void ProxyEndpointRejectsHttpByDefault()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentException>(() => options.ProxyEndpoint = new Uri("http://proxy.example.test:8080"));
    }

    /// <summary>
    /// Verifies that unsupported TLS modes are rejected before an HTTP client is created.
    /// </summary>
    [TestMethod]
    public void TlsModeRejectsUndefinedValue()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => options.TlsMode = (GitHubSecretLiveValidatorTlsMode)42);
    }

    /// <summary>
    /// Verifies that strict TLS mode configures the HTTP handler for TLS 1.2 or later.
    /// </summary>
    [TestMethod]
    public void TlsModeConfiguresHttpClientHandler()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        options.TlsMode = GitHubSecretLiveValidatorTlsMode.Tls12OrLater;
        using SocketsHttpHandler handler = CreateHttpClientHandler(options);

        Assert.AreEqual(SslProtocols.Tls12 | SslProtocols.Tls13, handler.SslOptions.EnabledSslProtocols);
    }

    /// <summary>
    /// Verifies that the default HTTP handler blocks non-public addresses resolved at connect time.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task VerifyAsyncBlocksNonPublicAddressResolvedAtConnectTime()
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        options.UserEndpoint = new Uri("https://8.8.8.8/user");
        options.MaxRetryAttempts = 0;
        int resolverCalls = 0;
        options.SetAddressResolver((_, _) =>
        {
            resolverCalls++;
            return new ValueTask<IPAddress[]>([IPAddress.Loopback]);
        });
        GitHubSecretLiveValidator validator = new(options);

        SecretValidationResult result = await validator.VerifyAsync(CreateFinding(), TestContext.CancellationToken);

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("GitHub verification request failed", result.Reason);
        Assert.AreEqual(1, resolverCalls);
    }

    private static GitHubSecretLiveValidator CreateValidator(
        FakeHttpMessageHandler handler,
        Action<GitHubSecretLiveValidatorOptions>? configureOptions = null)
    {
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        options.UserEndpoint = new Uri("https://api.github.test/user");
        options.SetMessageHandlerFactory(() => handler);
        configureOptions?.Invoke(options);
        return new GitHubSecretLiveValidator(options);
    }

    private static SocketsHttpHandler CreateHttpClientHandler(GitHubSecretLiveValidatorOptions options)
    {
        MethodInfo method = typeof(GitHubSecretLiveValidatorOptions).GetMethod(
            "CreateHttpClientHandler",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Expected GitHub options to expose an HTTP handler factory.");
        return method.Invoke(options, null) as SocketsHttpHandler
            ?? throw new InvalidOperationException("Expected GitHub options to create a SocketsHttpHandler.");
    }

    private static Finding CreateFinding(string? secret = null, string ruleId = "github-pat")
    {
        secret ??= CreateGitHubPat();
        return new Finding(
            ruleId,
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
            string.Concat("secret.txt:", ruleId, ":1"));
    }

    private static string CreateGitHubPat()
    {
        return CreateGitHubClassicToken("ghp_");
    }

    private static string CreateGitHubClassicToken(string prefix)
    {
        return string.Concat(prefix, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    private static string CreateGitHubFineGrainedPat()
    {
        return CreateGitHubFineGrainedPat("github_pat_");
    }

    private static string CreateGitHubFineGrainedPat(string prefix)
    {
        return string.Concat(
            prefix,
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789");
    }

    private static string CreateGitHubStatelessInstallationToken()
    {
        return string.Concat(
            "ghs_123456_",
            new string('a', 32),
            ".",
            new string('b', 256),
            ".",
            new string('c', 128));
    }
}
