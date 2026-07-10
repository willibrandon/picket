namespace Picket.Sources;

/// <summary>
/// Identifies the credential transport used for Bitbucket Data Center source requests.
/// </summary>
public enum BitbucketDataCenterCredentialKind
{
    /// <summary>
    /// Sends an HTTP access token through bearer authentication.
    /// </summary>
    BearerToken,

    /// <summary>
    /// Sends a username and password or user token through HTTP Basic authentication.
    /// </summary>
    Basic,
}
