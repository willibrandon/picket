namespace Picket.Sources;

/// <summary>
/// Identifies the credential transport used for Azure Blob Storage source enumeration.
/// </summary>
public enum AzureBlobCredentialKind
{
    /// <summary>
    /// Sends the credential as a bearer token in the Authorization header.
    /// </summary>
    BearerToken,

    /// <summary>
    /// Appends the credential as a shared access signature query string.
    /// </summary>
    SharedAccessSignature,
}
