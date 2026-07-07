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
    /// Verifies that database connection URL findings receive database-specific triage guidance.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesDatabaseConnectionUrls()
    {
        string connectionUrl = CreateDatabaseConnectionUrl();
        Finding finding = CreateDatabaseFinding(connectionUrl);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("Database", analysis.Provider);
        Assert.AreEqual("Database connection URL", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("databaseScheme=postgresql", analysis.Evidence);
        Assert.Contains("databaseUser=app_user", analysis.Evidence);
        Assert.Contains("Rotate the database password", string.Join('\n', analysis.RecommendedActions));
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.IsEmpty(analysis.RevocationCommands);
        Assert.Contains("Identify the database user", string.Join('\n', analysis.RevocationGuidance));
        Assert.DoesNotContain(connectionUrl, string.Join('\n', analysis.Evidence));
        Assert.DoesNotContain("picket-db-password-123", string.Join('\n', analysis.Evidence));
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
    /// Verifies that GitLab personal access token findings receive GitLab-specific triage guidance without printing the token.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesGitLabPersonalAccessTokens()
    {
        string token = CreateGitLabPat();
        Finding finding = CreateGitLabPatFinding(token);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GitLab", analysis.Provider);
        Assert.AreEqual("GitLab personal access token", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("gitLabRuleId=gitlab-pat", analysis.Evidence);
        Assert.Contains("resourceType=personal-access-token", analysis.Evidence);
        Assert.Contains("Review token scopes", string.Join('\n', analysis.RecommendedActions));
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.Contains("personal_access_tokens/<token-id>", string.Join('\n', analysis.RevocationCommands));
        Assert.Contains("Identify the owning GitLab user", string.Join('\n', analysis.RevocationGuidance));
        Assert.DoesNotContain(token, string.Join('\n', analysis.RevocationCommands));
        Assert.DoesNotContain(token, string.Join('\n', analysis.Evidence));
    }

    /// <summary>
    /// Verifies that GitLab CI job token findings receive containment guidance without unsafe command templates.
    /// </summary>
    [TestMethod]
    public void AnalyzeRecognizesGitLabCiJobTokens()
    {
        string token = CreateGitLabCiJobToken();
        Finding finding = CreateGitLabCiJobTokenFinding(token);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("GitLab", analysis.Provider);
        Assert.AreEqual("GitLab CI/CD job token", analysis.CredentialType);
        Assert.Contains("resourceType=ci-job-token", analysis.Evidence);
        Assert.IsTrue(analysis.RevocationAvailable);
        Assert.IsEmpty(analysis.RevocationCommands);
        Assert.Contains("Cancel the exposing pipeline if it is still running", string.Join('\n', analysis.RevocationGuidance));
        Assert.DoesNotContain(token, string.Join('\n', analysis.RevocationGuidance));
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

    private static Finding CreateDatabaseFinding(string connectionUrl)
    {
        return new Finding(
            "picket-database-connection-url",
            "Detected a database connection URL with embedded user credentials.",
            1,
            1,
            1,
            connectionUrl.Length,
            connectionUrl,
            connectionUrl,
            "settings.env",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["picket", "database", "connection-url"],
            "settings.env:picket-database-connection-url:1",
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

    private static Finding CreateGitLabPatFinding(string token)
    {
        return new Finding(
            "gitlab-pat",
            "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
            1,
            1,
            1,
            token.Length,
            token,
            token,
            "gitlab.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["gitlab"],
            "gitlab.txt:gitlab-pat:1",
            validationState: "structurally-valid");
    }

    private static Finding CreateGitLabCiJobTokenFinding(string token)
    {
        string match = $"CI_JOB_TOKEN={token}";
        return new Finding(
            "gitlab-cicd-job-token",
            "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
            1,
            1,
            1,
            match.Length,
            match,
            token,
            "pipeline.log",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            ["gitlab", "ci"],
            "pipeline.log:gitlab-cicd-job-token:1",
            validationState: "structurally-valid");
    }

    private static string CreateGoogleApiKey()
    {
        return string.Concat("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
    }

    private static string CreateGitHubPat()
    {
        return CreateGitHubClassicToken("ghp_");
    }

    private static string CreateGitLabPat()
    {
        return string.Concat("glpat-", "0123456789abcdefghijklmnopqrstuv");
    }

    private static string CreateGitLabCiJobToken()
    {
        return string.Concat("glcbt-", "0123456789abcdefghijklmnopqrstuv");
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

    private static string CreateDatabaseConnectionUrl()
    {
        return "postgresql://app_user:picket-db-password-123@db.internal.local:5432/appdb?sslmode=require";
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
