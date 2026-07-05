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
        Finding finding = CreateFinding(accountKey);

        CredentialAnalysis analysis = CredentialAnalyzer.Analyze(finding);

        Assert.AreEqual("Azure", analysis.Provider);
        Assert.AreEqual("Azure Storage account key", analysis.CredentialType);
        Assert.AreEqual("critical", analysis.Risk);
        Assert.Contains("accountName=picketstorage", analysis.Evidence);
        Assert.Contains("Rotate one Azure Storage account key", string.Join('\n', analysis.RecommendedActions));
        Assert.DoesNotContain(accountKey, string.Join('\n', analysis.Evidence));
    }

    private static Finding CreateFinding(string accountKey)
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

    private static string CreateAzureStorageAccountKey()
    {
        return Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Concat(
            "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "WXYZabcdefghijklmnopqrstuvwxyz01")));
    }
}
