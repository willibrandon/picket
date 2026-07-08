namespace Picket.Sources;

/// <summary>
/// Identifies the credential transport used for Bitbucket Cloud source requests.
/// </summary>
public enum BitbucketCredentialKind
{
    /// <summary>
    /// Sends an OAuth, workspace, project, repository, or API token through HTTP Bearer authentication.
    /// </summary>
    BearerToken,

    /// <summary>
    /// Sends a username and app password through HTTP Basic authentication.
    /// </summary>
    AppPassword,
}
