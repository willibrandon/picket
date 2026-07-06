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
            "github",
            "v1",
            new Uri("https://metadata.google.internal/latest/meta-data"),
            new SecretValidationResult(SecretValidationState.Active));
        var verifier = new SecretLiveVerifier([validator]);

        SecretValidationResult result = await verifier.VerifyAsync(CreateFinding());

        Assert.AreEqual(SecretValidationState.Error, result.State);
        Assert.Contains("MetadataHost", result.Reason);
        Assert.AreEqual(0, validator.VerifyCount);
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
        var validator = new FakeSecretLiveValidator(
            "github",
            "v1",
            new Uri("https://localhost/user"),
            new SecretValidationResult(SecretValidationState.Active, "provider accepted token"));
        var verifier = new SecretLiveVerifier([validator], cache, options);
        Finding finding = CreateFinding();

        SecretValidationResult first = await verifier.VerifyAsync(finding);
        SecretValidationResult second = await verifier.VerifyAsync(finding);

        Assert.AreEqual(SecretValidationState.Active, first.State);
        Assert.AreEqual(SecretValidationState.Active, second.State);
        Assert.AreEqual(1, validator.VerifyCount);
    }

    private static Finding CreateFinding()
    {
        const string Secret = "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        return new Finding(
            "github-pat",
            "GitHub token",
            1,
            1,
            1,
            Secret.Length,
            Secret,
            Secret,
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
}
