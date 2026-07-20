using Picket.Engine;
using Picket.Verify;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="OfflineSecretValidator" />.
/// </summary>
[TestClass]
public sealed class OfflineSecretValidatorTests
{
    /// <summary>
    /// Verifies that report values include offline and live validation states.
    /// </summary>
    [TestMethod]
    public void ToReportValueFormatsValidationStates()
    {
        Assert.AreEqual("unknown", SecretValidationResult.ToReportValue(SecretValidationState.Unknown));
        Assert.AreEqual("structurally-valid", SecretValidationResult.ToReportValue(SecretValidationState.StructurallyValid));
        Assert.AreEqual("test-credential", SecretValidationResult.ToReportValue(SecretValidationState.TestCredential));
        Assert.AreEqual("invalid", SecretValidationResult.ToReportValue(SecretValidationState.Invalid));
        Assert.AreEqual("active", SecretValidationResult.ToReportValue(SecretValidationState.Active));
        Assert.AreEqual("inactive", SecretValidationResult.ToReportValue(SecretValidationState.Inactive));
        Assert.AreEqual("skipped", SecretValidationResult.ToReportValue(SecretValidationState.Skipped));
        Assert.AreEqual("error", SecretValidationResult.ToReportValue(SecretValidationState.Error));
    }

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
    /// Verifies that native AWS access key pairs are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesAwsAccessKeyPairShape()
    {
        string secretAccessKey = CreateAwsSecretAccessKey();
        Finding finding = CreateFinding(
            "picket-aws-access-key-pair",
            secretAccessKey,
            $"aws_access_key_id = {CreateAwsAccessKeyId()}\naws_secret_access_key = {secretAccessKey}");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that malformed native AWS access key pairs are rejected offline.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsMalformedAwsAccessKeyPair()
    {
        Finding finding = CreateFinding(
            "picket-aws-access-key-pair",
            "too-short",
            $"aws_access_key_id = {CreateAwsAccessKeyId()}\naws_secret_access_key = too-short");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that exact known provider examples are identified as test credentials.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesKnownProviderExampleCredential()
    {
        Finding finding = CreateFinding("aws-access-token", CreateAwsExampleAccessKeyId());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.TestCredential, result.State);
        Assert.AreEqual("test-credential", result.ReportValue);
    }

    /// <summary>
    /// Verifies that broad placeholder heuristics do not override valid provider token structure.
    /// </summary>
    [TestMethod]
    public void ValidateKeepsStructurallyValidProviderTokenWithPlaceholderSubstring()
    {
        Finding finding = CreateFinding("github-pat", string.Concat("ghp_", "0123456789fakeABCDEFGHIJKLMNOPQRSTUV"));

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that broad repeated-pattern heuristics do not override valid provider token structure.
    /// </summary>
    [TestMethod]
    public void ValidateKeepsStructurallyValidProviderTokenWithRepeatedPattern()
    {
        Finding finding = CreateFinding("github-pat", string.Concat("ghp_", "abcabcabcabcabcabcabcabcabcabcabcabc"));

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that repeated-pattern fixture values are still identified when no provider structure applies.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesRepeatedPatternUnknownCredentials()
    {
        Finding finding = CreateFinding("custom-token", "abcabcabcabcabcabcabcabcabcabcabcabc");

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
    /// Verifies that native GitHub token families are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesNativeGitHubTokenShapes()
    {
        (string RuleId, string Secret)[] cases = [
            ("picket-github-app-token", CreateGitHubClassicToken("ghs_")),
            ("picket-github-fine-grained-personal-access-token", CreateGitHubFineGrainedPat()),
            ("picket-github-oauth-token", CreateGitHubClassicToken("gho_")),
            ("picket-github-personal-access-token", CreateGitHubPat()),
            ("picket-github-refresh-token", CreateGitHubClassicToken("ghr_")),
        ];

        for (int i = 0; i < cases.Length; i++)
        {
            Finding finding = CreateFinding(cases[i].RuleId, cases[i].Secret);

            SecretValidationResult result = OfflineSecretValidator.Validate(finding);

            Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
            Assert.AreEqual("structurally-valid", result.ReportValue);
        }
    }

    /// <summary>
    /// Verifies that Codex refresh-token validation requires the provider-specific shape.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsGenericCodexRefreshToken()
    {
        Finding finding = CreateFinding(
            "picket-openai-codex-refresh-token",
            "another-provider-refresh-token-value-1234567890");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
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
    /// Verifies that database connection URLs with embedded credentials are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesDatabaseConnectionUrlShape()
    {
        Finding finding = CreateFinding("picket-database-connection-url", CreateDatabaseConnectionUrl());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that database connection URLs without passwords are rejected by offline validation.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsPasswordlessDatabaseConnectionUrl()
    {
        Finding finding = CreateFinding(
            "picket-database-connection-url",
            "postgresql://app_user@db.internal.local:5432/appdb");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that GCP API keys are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesGcpApiKeyShape()
    {
        Finding finding = CreateFinding("gcp-api-key", CreateGcpApiKey());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that native Google API key findings are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesNativeGoogleApiKeyShape()
    {
        Finding finding = CreateFinding("picket-google-api-key", CreateGcpApiKey());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that malformed GCP API keys are rejected.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsMalformedGcpApiKey()
    {
        Finding finding = CreateFinding("gcp-api-key", string.Concat("AIza", "too-short"));

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that Sourcegraph access tokens are structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesSourcegraphAccessTokenShape()
    {
        Finding finding = CreateFinding("picket-sourcegraph-access-token", CreateSourcegraphAccessToken());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that bare 40-hex values are not accepted as native Sourcegraph tokens.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsBareSourcegraphHexTokenShape()
    {
        Finding finding = CreateFinding("picket-sourcegraph-access-token", "0123456789abcdef0123456789abcdef01234567");

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.Invalid, result.State);
        Assert.AreEqual("invalid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that GCP service account key JSON is structurally validated offline.
    /// </summary>
    [TestMethod]
    public void ValidateRecognizesGcpServiceAccountKeyJson()
    {
        Finding finding = CreateFinding("picket-gcp-service-account-key", CreateGcpServiceAccountKeyJson());

        SecretValidationResult result = OfflineSecretValidator.Validate(finding);

        Assert.AreEqual(SecretValidationState.StructurallyValid, result.State);
        Assert.AreEqual("structurally-valid", result.ReportValue);
    }

    /// <summary>
    /// Verifies that malformed GCP service account key JSON is rejected.
    /// </summary>
    [TestMethod]
    public void ValidateRejectsMalformedGcpServiceAccountKeyJson()
    {
        Finding finding = CreateFinding(
            "picket-gcp-service-account-key",
            CreateGcpServiceAccountKeyJson(tokenUri: "https://metadata.google.internal/token"));

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

    private static string CreateAwsSecretAccessKey()
    {
        return string.Concat("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
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

    private static string CreateDatabaseConnectionUrl()
    {
        return "postgresql://app_user:picket-db-password-123@db.internal.local:5432/appdb?sslmode=require";
    }

    private static string CreateSourcegraphAccessToken()
    {
        return string.Concat("sgp_", "0123456789abcdef", "_", "0123456789abcdef0123456789abcdef01234567");
    }

    private static string CreateGcpApiKey()
    {
        return string.Concat("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
    }

    private static string CreateGcpServiceAccountKeyJson(string tokenUri = "https://oauth2.googleapis.com/token")
    {
        return $$"""
            {
              "type": "service_account",
              "project_id": "picket-prod-123",
              "private_key_id": "0123456789abcdef0123456789abcdef01234567",
              "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Yz0123456789abcd\n-----END PRIVATE KEY-----\n",
              "client_email": "scanner-sa@picket-prod-123.iam.gserviceaccount.com",
              "client_id": "123456789012345678901",
              "auth_uri": "https://accounts.google.com/o/oauth2/auth",
              "token_uri": "{{tokenUri}}"
            }
            """;
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
