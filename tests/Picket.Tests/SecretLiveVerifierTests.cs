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

    private static Finding CreateFinding()
    {
        string secret = CreateGitHubPat();
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
}
