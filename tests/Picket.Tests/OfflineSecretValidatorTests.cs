using System.Text;
using Picket.Engine;
using Picket.Verify;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="OfflineSecretValidator" />.
/// </summary>
[TestClass]
public sealed class OfflineSecretValidatorTests
{
    /// <summary>
    /// Verifies that AWS access key IDs are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesAwsAccessKeyIdShape()
    {
        Finding finding = CreateFinding("aws-access-token", CreateAwsAccessKeyId());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that known placeholder markers are identified before provider-specific validation.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesTestCredentialMarkers()
    {
        Finding finding = CreateFinding("aws-access-token", CreateAwsExampleAccessKeyId());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.TestCredential, result.State);
        Assert.AreEqual("test-credential", result.ReportValue);
    }

    /// <summary>
    /// Verifies that GitHub classic token families are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesGitHubClassicTokenShape()
    {
        Finding finding = CreateFinding("github-pat", CreateGitHubPat());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
    }

    /// <summary>
    /// Verifies that known provider tokens that fail structural checks are marked invalid.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsInvalidKnownProviderShape()
    {
        Finding finding = CreateFinding("github-pat", string.Concat("ghp", "_invalid"));

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that JWT header, payload, and signature structure is validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesJwtStructure()
    {
        Finding finding = CreateFinding("jwt", CreateJwt());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that JWTs with malformed claim payloads are rejected.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsMalformedJwtPayload()
    {
        Finding finding = CreateFinding("jwt", string.Concat(CreateJwtHeader(), ".", "bm90LWpzb24", ".", "c2ln"));

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that Base64-wrapped JWTs are decoded and structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesBase64EncodedJwtStructure()
    {
        string encodedJwt = Convert.ToBase64String(Encoding.UTF8.GetBytes(CreateJwt()));
        Finding finding = CreateFinding("jwt-base64", encodedJwt);

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that Azure Storage connection strings are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesAzureStorageConnectionStringShape()
    {
        string accountKey = CreateAzureStorageAccountKey();
        string connectionString = CreateAzureStorageConnectionString(accountKey);
        Finding finding = CreateFinding(
            "picket-azure-storage-connection-string",
            accountKey,
            connectionString);

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that malformed Azure Storage account keys are rejected.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsMalformedAzureStorageAccountKey()
    {
        string accountKey = Convert.ToBase64String(Encoding.UTF8.GetBytes("too-short"));
        string connectionString = CreateAzureStorageConnectionString(accountKey);
        Finding finding = CreateFinding(
            "picket-azure-storage-connection-string",
            accountKey,
            connectionString);

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that unknown rule families remain explicitly unknown.
    /// </summary>
    [TestMethod]
    public void ValidateKeepsUnknownRulesUnknown()
    {
        Finding finding = CreateFinding("custom-token", "token-12345");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Unknown, result.State);
        Assert.AreEqual("unknown", result.ReportValue);
    }

    /// <summary>
    /// Verifies that annotation preserves finding fields while adding a native report state.
    /// </summary>
    [TestMethod]
    public void AnnotateAddsValidationState()
    {
        Finding finding = CreateFinding("github-pat", CreateGitHubPat());

        Finding annotated = OfflineSecretValidator.Annotate(finding);

        Assert.AreEqual(finding.RuleID, annotated.RuleID);
        Assert.AreEqual(finding.Secret, annotated.Secret);
        Assert.AreEqual("structurally-valid", annotated.ValidationState);
    }

    private static Finding CreateFinding(string ruleId, string secret, string? match = null)
    {
        match ??= secret;
        return new Finding(
            ruleId,
            "description",
            1,
            1,
            1,
            match.Length,
            match,
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
            "secret.txt:rule:1");
    }

    private static string CreateAwsAccessKeyId()
    {
        return string.Concat("AKIA", "IOSFODNN7ABCDE23");
    }

    private static string CreateAwsExampleAccessKeyId()
    {
        return string.Concat("AKIA", "IOSFODNN7EXAMPLE");
    }

    private static string CreateGitHubPat()
    {
        return string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    private static string CreateAzureStorageConnectionString(string accountKey)
    {
        return $"DefaultEndpointsProtocol=https;AccountName=picketstorage;AccountKey={accountKey};EndpointSuffix=core.windows.net";
    }

    private static string CreateAzureStorageAccountKey()
    {
        return Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Concat(
            "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "WXYZabcdefghijklmnopqrstuvwxyz01")));
    }

    private static string CreateJwt()
    {
        return string.Concat(
            CreateJwtHeader(),
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    private static string CreateJwtHeader()
    {
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    }
}
