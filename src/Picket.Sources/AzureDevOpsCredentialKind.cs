namespace Picket.Sources;

/// <summary>
/// Identifies the credential transport used for Azure DevOps source requests.
/// </summary>
public enum AzureDevOpsCredentialKind
{
    /// <summary>
    /// Sends an Azure DevOps personal access token through HTTP Basic authentication.
    /// </summary>
    PersonalAccessToken,

    /// <summary>
    /// Sends an Azure Pipelines job token or Microsoft Entra token through HTTP Bearer authentication.
    /// </summary>
    BearerToken,
}
