using System.Text;
using Picket.Analyze;
using Picket.Engine;

namespace Picket.Tests;

/// <summary>
/// Tests offline credential analysis.
/// </summary>
[TestClass]
public sealed class CredentialAnalyzerTests
{
    /// <summary>
    /// Verifies that Azure Storage connection-string findings receive Azure-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesAzureStorageConnectionStrings()
    {
        string accountKey = CreateAzureStorageAccountKey();
        Finding finding = CreateAzureFinding(accountKey);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("Azure", analysis.Provider);
        Assert.AreEqual("Azure Storage account key", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("accountName=picketstorage", analysis.Evidence);
        Assert.Contains("Rotate one Azure Storage account key", string.Join('\n', analysis.RecommendedActions));
        Assert.DoesNotContain(accountKey, string.Join('\n', analysis.Evidence));
    }

    /// <summary>
    /// Verifies that native AWS access key pair findings receive AWS-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesAwsAccessKeyPairs()
    {
        string accessKeyId = CreateAwsAccessKeyId();
        string secretAccessKey = CreateAwsSecretAccessKey();
        Finding finding = CreateAwsFinding(accessKeyId, secretAccessKey);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("AWS", analysis.Provider);
        Assert.AreEqual("AWS access key pair", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains($"accessKeyId={accessKeyId}", analysis.Evidence);
        Assert.Contains("resourceType=access key", analysis.Evidence);
        Assert.Contains("Disable or rotate the leaked AWS access key", string.Join('\n', analysis.RecommendedActions));
        Assert.DoesNotContain(secretAccessKey, string.Join('\n', analysis.Evidence));
    }

    /// <summary>
    /// Verifies that GCP service account key findings receive GCP-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesGcpServiceAccountKeys()
    {
        string serviceAccountJson = CreateGcpServiceAccountKeyJson();
        Finding finding = CreateGcpFinding(serviceAccountJson);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GCP", analysis.Provider);
        Assert.AreEqual("GCP service account key", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("projectId=picket-prod-123", analysis.Evidence);
        Assert.Contains("clientEmail=scanner-sa@picket-prod-123.iam.gserviceaccount.com", analysis.Evidence);
        Assert.Contains("Disable or delete the leaked service account key", string.Join('\n', analysis.RecommendedActions));
        Assert.DoesNotContain(serviceAccountJson, string.Join('\n', analysis.Evidence));
    }

    /// <summary>
    /// Verifies that GCP API-key findings receive API-key-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesGcpApiKeys()
    {
        Finding finding = CreateGcpApiKeyFinding();

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GCP", analysis.Provider);
        Assert.AreEqual("GCP API key", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("Review and tighten API key restrictions", string.Join('\n', analysis.RecommendedActions));
    }

    private static Finding CreateAzureFinding(string accountKey)
    {
        string connectionString = $"DefaultEndpointsProtocol=https;AccountName=picketstorage;AccountKey={accountKey};EndpointSuffix=core.windows.net";
        return new Finding(
            "picket-azure-storage-connection-string",
            "Detected an Azure Storage connection string with an account key.",
            1,
            1,
            1,
            connectionString.Length,
            connectionString,
            accountKey,
            "settings.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "azure", "storage"],
            "settings.txt:picket-azure-storage-connection-string:1",
            validationState: "structurally-valid");
    }

    private static Finding CreateAwsFinding(string accessKeyId, string secretAccessKey)
    {
        string match = $"aws_access_key_id = {accessKeyId}\naws_secret_access_key = {secretAccessKey}";
        return new Finding(
            "picket-aws-access-key-pair",
            "Detected an AWS access key ID paired with a secret access key.",
            1,
            2,
            1,
            61,
            match,
            secretAccessKey,
            "credentials.ini",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "aws", "access-key"],
            "credentials.ini:picket-aws-access-key-pair:1",
            validationState: "structurally-valid");
    }

    private static Finding CreateGcpApiKeyFinding()
    {
        const string Secret = "AIzaSyDabcdefghijklmnopqrstuvwxyz123456";
        return new Finding(
            "gcp-api-key",
            "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
            1,
            1,
            1,
            Secret.Length,
            Secret,
            Secret,
            "settings.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["google"],
            "settings.txt:gcp-api-key:1",
            validationState: "structurally-valid");
    }

    private static Finding CreateGcpFinding(string serviceAccountJson)
    {
        return new Finding(
            "picket-gcp-service-account-key",
            "Detected a Google Cloud service account key JSON document.",
            1,
            10,
            1,
            2,
            serviceAccountJson,
            serviceAccountJson,
            "service-account.json",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "gcp", "service-account"],
            "service-account.json:picket-gcp-service-account-key:1",
            validationState: "structurally-valid");
    }

    private static string CreateAzureStorageAccountKey()
    {
        return Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Concat(
            "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "WXYZabcdefghijklmnopqrstuvwxyz01")));
    }

    private static string CreateAwsAccessKeyId()
    {
        return string.Concat("AKIA", "XYZDQCEN4B6JSJQI");
    }

    private static string CreateAwsSecretAccessKey()
    {
        return string.Concat("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
    }

    private static string CreateGcpServiceAccountKeyJson()
    {
        return """
            {
              "type": "service_account",
              "project_id": "picket-prod-123",
              "private_key_id": "0123456789abcdef0123456789abcdef01234567",
              "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Yz0123456789abcd\n-----END PRIVATE KEY-----\n",
              "client_email": "scanner-sa@picket-prod-123.iam.gserviceaccount.com",
              "client_id": "123456789012345678901",
              "auth_uri": "https://accounts.google.com/o/oauth2/auth",
              "token_uri": "https://oauth2.googleapis.com/token"
            }
            """;
    }
}
