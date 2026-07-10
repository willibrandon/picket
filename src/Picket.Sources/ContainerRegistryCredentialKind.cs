namespace Picket.Sources;

/// <summary>
/// Identifies the credential form used to pull a container image from a registry.
/// </summary>
public enum ContainerRegistryCredentialKind
{
    /// <summary>
    /// Pull the image without configured credentials.
    /// </summary>
    Anonymous,

    /// <summary>
    /// Send a pre-issued bearer token to the registry.
    /// </summary>
    BearerToken,

    /// <summary>
    /// Use a username and password or personal access token for registry authentication.
    /// </summary>
    Basic,
}
