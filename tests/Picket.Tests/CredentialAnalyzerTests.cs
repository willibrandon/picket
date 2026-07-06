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
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains(
            "az storage account keys renew --account-name picketstorage --resource-group <resource-group> --key primary",
            analysis.RevocationCommands);
        Assert.Contains("Move consumers to the alternate storage account key before regenerating the compromised key.", analysis.RevocationGuidance);
        Assert.DoesNotContain(accountKey, string.Join('\n', analysis.Evidence));
        Assert.DoesNotContain(accountKey, string.Join('\n', analysis.RevocationCommands));
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
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains($"aws iam update-access-key --access-key-id {accessKeyId} --status Inactive --user-name <iam-user>", analysis.RevocationCommands);
        Assert.Contains($"aws iam delete-access-key --access-key-id {accessKeyId} --user-name <iam-user>", analysis.RevocationCommands);
        Assert.DoesNotContain(secretAccessKey, string.Join('\n', analysis.Evidence));
        Assert.DoesNotContain(secretAccessKey, string.Join('\n', analysis.RevocationCommands));
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
        Assert.Contains("privateKeyId=0123456789abcdef0123456789abcdef01234567", analysis.Evidence);
        Assert.Contains("Disable or delete the leaked service account key", string.Join('\n', analysis.RecommendedActions));
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains(
            "gcloud iam service-accounts keys delete 0123456789abcdef0123456789abcdef01234567 --iam-account=scanner-sa@picket-prod-123.iam.gserviceaccount.com",
            analysis.RevocationCommands);
        Assert.DoesNotContain(serviceAccountJson, string.Join('\n', analysis.Evidence));
        Assert.DoesNotContain(serviceAccountJson, string.Join('\n', analysis.RevocationCommands));
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
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains("gcloud services api-keys delete <key-id> --project <project-id> --location global", analysis.RevocationCommands);
    }

    /// <summary>
    /// Verifies that native Google API-key findings receive API-key-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesNativeGoogleApiKeys()
    {
        Finding finding = CreateNativeGoogleApiKeyFinding();

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GCP", analysis.Provider);
        Assert.AreEqual("GCP API key", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("Review and tighten API key restrictions", string.Join('\n', analysis.RecommendedActions));
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains("Find the API key resource in Google Cloud API Keys before deleting or replacing it.", analysis.RevocationGuidance);
    }

    /// <summary>
    /// Verifies that native GitHub token findings receive GitHub-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesNativeGitHubPersonalAccessTokens()
    {
        string token = CreateGitHubPat();
        Finding finding = CreateNativeGitHubPatFinding(token);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GitHub", analysis.Provider);
        Assert.AreEqual("GitHub personal access token", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("Rotate or revoke the GitHub token", string.Join('\n', analysis.RecommendedActions));
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains("<github-token>", string.Join('\n', analysis.RevocationCommands));
        Assert.Contains("https://api.github.com/credentials/revoke", string.Join('\n', analysis.RevocationCommands));
        Assert.Contains("Submit the leaked token to GitHub's credential revocation API or revoke it from the owner's token settings.", analysis.RevocationGuidance);
        Assert.DoesNotContain(token, string.Join('\n', analysis.RevocationCommands));
        Assert.DoesNotContain(token, string.Join('\n', analysis.Evidence));
    }

    /// <summary>
    /// Verifies that live provider metadata enriches incident-response analysis.
    /// </summary>
    [TestMethod]
    public void AnalyzeUsesLiveProviderMetadata()
    {
        string token = CreateGitHubPat();
        Finding finding = CreateNativeGitHubPatFinding(token, validationState: "active");
        var metadata = new CredentialAnalysisMetadata(
            "octocat",
            ["repo", "gist"],
            ["github:user"],
            ["githubLogin=octocat"]);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding, metadata);

        Assert.AreEqual("active", analysis.ValidationState);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.AreEqual("octocat", analysis.Identity);
        Assert.Contains("repo", analysis.Scopes);
        Assert.Contains("gist", analysis.Scopes);
        Assert.Contains("github:user", analysis.ReachableResources);
        Assert.Contains("githubLogin=octocat", analysis.Evidence);
        Assert.DoesNotContain(token, string.Join('\n', analysis.Evidence));
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
        string secret = CreateGoogleApiKey();
        return new Finding(
            "gcp-api-key",
            "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
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

    private static Finding CreateNativeGoogleApiKeyFinding()
    {
        string secret = CreateGoogleApiKey();
        return new Finding(
            "picket-google-api-key",
            "Detected a Google API key.",
            1,
            1,
            1,
            secret.Length,
            secret,
            secret,
            "settings.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "google"],
            "settings.txt:picket-google-api-key:1",
            validationState: "structurally-valid");
    }

    private static Finding CreateNativeGitHubPatFinding(string token, string validationState = "structurally-valid")
    {
        return new Finding(
            "picket-github-personal-access-token",
            "Detected a GitHub personal access token.",
            1,
            1,
            1,
            token.Length,
            token,
            token,
            "settings.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "github"],
            "settings.txt:picket-github-personal-access-token:1",
            validationState: validationState);
    }

    private static string CreateGoogleApiKey()
    {
        return string.Concat("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
    }

    private static string CreateGitHubPat()
    {
        return CreateGitHubClassicToken("ghp_");
    }

    private static string CreateGitHubClassicToken(string prefix)
    {
        return string.Concat(prefix, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
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
