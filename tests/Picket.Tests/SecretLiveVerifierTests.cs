using Picket.Engine;
using Picket.Security;
using Picket.Verify;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="SecretLiveVerifier" />.
/// </summary>
[TestClass]
public sealed class SecretLiveVerifierTests
{
    /// <summary>
    /// Gets or sets the current MSTest context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that unsupported findings are skipped without contacting a validator.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncSkipsUnsupportedFindings()
    {
        var validator = new FakeSecretLiveValidator(
            "github",
            "v1",
            new Uri("https://metadata.google.internal/"),
            new SecretValidationResult(SecretValidationState.Active),
            _ => false);
        var verifier = new SecretLiveVerifier([validator]);

        SecretValidationResult result = await verifier.VerifyAsync(CreateFinding());

        Assert.AreEqual(SecretValidationState.Skipped, result.State);
        Assert.AreEqual(0, validator.VerifyCount);
    }

    /// <summary>
    /// Verifies that endpoint safety is evaluated before a provider validator can run.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncBlocksUnsafeEndpointsBeforeValidatorRuns()
    {
        var validator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://metadata.google.internal/latest/meta-data"),
            new SecretValidationResult(SecretValidationState.Active));
        var verifier = new SecretLiveVerifier([validator]);

        SecretValidationResult result = await verifier.VerifyAsync(CreateFinding());

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("MetadataHost", result.Reason);
        Assert.Contains("provider=fake", result.Evidence);
        Assert.Contains("endpoint=https://metadata.google.internal/latest/meta-data", result.Evidence);
        Assert.Contains("endpointPolicy=blocked:MetadataHost", result.Evidence);
        Assert.Contains("providerContacted=false", result.Evidence);
        Assert.DoesNotContain("cacheHit=request", result.Evidence);
        Assert.DoesNotContain("cacheHit=persistent", result.Evidence);
        Assert.AreEqual(0, validator.VerifyCount);
    }

    /// <summary>
    /// Verifies that contacted provider results include non-secret audit evidence.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncAddsAuditEvidenceToProviderResults()
    {
        SecretLiveVerifierOptions options = SecretLiveVerifierOptions.CreateDefault();
        options.EndpointGuardOptions = new EndpointGuardOptions { AllowNonPublicAddresses = true };
        var validator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(
                SecretValidationState.Active,
                "provider accepted token",
                evidence: ["provider=fake", "endpoint=https://other.example/user", "custom=value"]));
        var verifier = new SecretLiveVerifier([validator], options: options);

        SecretValidationResult result = await verifier.VerifyAsync(CreateFinding());

        Assert.AreEqual(SecretValidationState.Active, result.State);
        Assert.Contains("provider=fake", result.Evidence);
        Assert.Contains("endpoint=https://127.0.0.1/user", result.Evidence);
        Assert.Contains("endpointPolicy=allowed", result.Evidence);
        Assert.Contains("providerContacted=true", result.Evidence);
        Assert.Contains("custom=value", result.Evidence);
        Assert.DoesNotContain("cacheHit=request", result.Evidence);
        Assert.DoesNotContain("cacheHit=persistent", result.Evidence);
        Assert.HasCount(1, FindEvidence(result, "provider="));
        Assert.HasCount(1, FindEvidence(result, "endpoint="));
    }

    /// <summary>
    /// Verifies that repeated live verifier results are read from the request cache.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncUsesRequestCache()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretLiveVerifierOptions options = SecretLiveVerifierOptions.CreateDefault();
        options.EndpointGuardOptions = new EndpointGuardOptions { AllowNonPublicAddresses = true };
        var validator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Active, "provider accepted token"));
        var verifier = new SecretLiveVerifier([validator], cache, options);
        Finding finding = CreateFinding();

        SecretValidationResult first = await verifier.VerifyAsync(finding);
        SecretValidationResult second = await verifier.VerifyAsync(finding);

        Assert.AreEqual(SecretValidationState.Active, first.State);
        Assert.AreEqual(SecretValidationState.Active, second.State);
        Assert.Contains("providerContacted=true", first.Evidence);
        Assert.Contains("providerContacted=false", second.Evidence);
        Assert.Contains("cacheHit=request", second.Evidence);
        Assert.AreEqual(1, validator.VerifyCount);
    }

    /// <summary>
    /// Verifies that live verifier results are read from the persistent cache.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncUsesPersistentCache()
    {
        using TempDirectory temp = TempDirectory.Create();
        SecretValidationCache cache = SecretValidationCache.Open(temp.Path, "rules:v1");
        SecretLiveVerifierOptions options = SecretLiveVerifierOptions.CreateDefault();
        options.EndpointGuardOptions = new EndpointGuardOptions { AllowNonPublicAddresses = true };
        var firstValidator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Active, "provider accepted token"));
        var firstVerifier = new SecretLiveVerifier([firstValidator], cache, options);
        Finding finding = CreateFinding();

        SecretValidationResult first = await firstVerifier.VerifyAsync(finding);

        var secondValidator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Inactive, "provider rejected token"));
        var secondVerifier = new SecretLiveVerifier([secondValidator], cache, options);

        SecretValidationResult second = await secondVerifier.VerifyAsync(finding);

        Assert.AreEqual(SecretValidationState.Active, first.State);
        Assert.AreEqual(SecretValidationState.Active, second.State);
        Assert.Contains("providerContacted=true", first.Evidence);
        Assert.Contains("providerContacted=false", second.Evidence);
        Assert.Contains("cacheHit=persistent", second.Evidence);
        Assert.AreEqual(1, firstValidator.VerifyCount);
        Assert.AreEqual(0, secondValidator.VerifyCount);
    }

    /// <summary>
    /// Verifies that the per-provider request limit is enforced before provider code runs.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task VerifyAsyncLimitsConcurrentRequestsPerProvider()
    {
        var release = new TaskCompletionSource<SecretValidationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        SecretLiveVerifierOptions options = SecretLiveVerifierOptions.CreateDefault();
        options.EndpointGuardOptions = new EndpointGuardOptions { AllowNonPublicAddresses = true };
        options.MaxConcurrentProviderRequests = 10;
        options.MaxConcurrentRequestsPerProvider = 1;
        var validator = new FakeSecretLiveValidator(
            "fake",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Active),
            verifyAsync: async (_, cancellationToken) => await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false));
        var verifier = new SecretLiveVerifier([validator], options: options);

        Task<SecretValidationResult> first = verifier.VerifyAsync(
            CreateFinding(CreateGitHubClassicToken("ghp_")),
            TestContext.CancellationToken).AsTask();
        await WaitUntilAsync(() => validator.VerifyCount == 1, TestContext.CancellationToken).ConfigureAwait(false);

        Task<SecretValidationResult> second = verifier.VerifyAsync(
            CreateFinding(CreateGitHubClassicToken("gho_")),
            TestContext.CancellationToken).AsTask();

        Assert.AreEqual(1, validator.VerifyCount);
        Assert.IsFalse(second.IsCompleted);

        release.SetResult(new SecretValidationResult(SecretValidationState.Active));
        await Task.WhenAll(first, second).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, validator.VerifyCount);
    }

    /// <summary>
    /// Verifies that the global provider request limit is enforced across providers.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task VerifyAsyncLimitsConcurrentRequestsGlobally()
    {
        var release = new TaskCompletionSource<SecretValidationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        SecretLiveVerifierOptions options = SecretLiveVerifierOptions.CreateDefault();
        options.EndpointGuardOptions = new EndpointGuardOptions { AllowNonPublicAddresses = true };
        options.MaxConcurrentProviderRequests = 1;
        options.MaxConcurrentRequestsPerProvider = 10;
        var firstValidator = new FakeSecretLiveValidator(
            "first",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Active),
            supports: finding => finding.RuleID.Equals("first-rule", StringComparison.Ordinal),
            verifyAsync: async (_, cancellationToken) => await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false));
        var secondValidator = new FakeSecretLiveValidator(
            "second",
            "v1",
            new Uri("https://127.0.0.1/user"),
            new SecretValidationResult(SecretValidationState.Active),
            supports: finding => finding.RuleID.Equals("second-rule", StringComparison.Ordinal),
            verifyAsync: async (_, cancellationToken) => await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false));
        var verifier = new SecretLiveVerifier([firstValidator, secondValidator], options: options);

        Task<SecretValidationResult> first = verifier.VerifyAsync(
            CreateFinding(CreateGitHubClassicToken("ghp_"), "first-rule"),
            TestContext.CancellationToken).AsTask();
        await WaitUntilAsync(() => firstValidator.VerifyCount == 1, TestContext.CancellationToken).ConfigureAwait(false);

        Task<SecretValidationResult> second = verifier.VerifyAsync(
            CreateFinding(CreateGitHubClassicToken("gho_"), "second-rule"),
            TestContext.CancellationToken).AsTask();

        Assert.AreEqual(0, secondValidator.VerifyCount);
        Assert.IsFalse(second.IsCompleted);

        release.SetResult(new SecretValidationResult(SecretValidationState.Active));
        await Task.WhenAll(first, second).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, firstValidator.VerifyCount);
        Assert.AreEqual(1, secondValidator.VerifyCount);
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

    private static List<string> FindEvidence(SecretValidationResult result, string prefix)
    {
        var values = new List<string>();
        for (int i = 0; i < result.Evidence.Count; i++)
        {
            if (result.Evidence[i].StartsWith(prefix, StringComparison.Ordinal))
            {
                values.Add(result.Evidence[i]);
            }
        }

        return values;
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, CancellationToken cancellationToken)
    {
        for (int i = 0; i < 100; i++)
        {
            if (predicate())
            {
                return;
            }

            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }

        Assert.Fail("Timed out waiting for live verifier test state.");
    }
}
