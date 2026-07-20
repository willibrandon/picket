namespace Picket.Rules;

/// <summary>
/// Defines the stable names of Picket's built-in structured detectors.
/// </summary>
public static class PicketBuiltInDetectorNames
{
    /// <summary>
    /// Gets the detector for Codex credential JSON documents.
    /// </summary>
    public const string CodexCredentials = "codex-credentials";

    /// <summary>
    /// Gets the detector for Docker registry credential JSON documents.
    /// </summary>
    public const string DockerRegistryCredentials = "docker-registry-credentials";

    /// <summary>
    /// Gets the detector for GCP service-account key JSON documents.
    /// </summary>
    public const string GcpServiceAccountKey = "gcp-service-account-key";

    /// <summary>
    /// Gets the detector for private JSON Web Keys.
    /// </summary>
    public const string JwkPrivateKey = "jwk-private-key";

    /// <summary>
    /// Gets the detector for Kubernetes Secret YAML documents.
    /// </summary>
    public const string KubernetesSecret = "kubernetes-secret";

    /// <summary>
    /// Gets the detector for credentials in Model Context Protocol server configurations.
    /// </summary>
    public const string McpServerCredentials = "mcp-server-credentials";

    /// <summary>
    /// Gets the detector for npm configuration credentials.
    /// </summary>
    public const string NpmCredentials = "npm-credentials";

    /// <summary>
    /// Returns whether a name identifies a built-in detector.
    /// </summary>
    /// <param name="name">The detector name.</param>
    /// <returns><see langword="true" /> when the name identifies a built-in detector.</returns>
    public static bool IsKnown(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return name is CodexCredentials
            or DockerRegistryCredentials
            or GcpServiceAccountKey
            or JwkPrivateKey
            or KubernetesSecret
            or McpServerCredentials
            or NpmCredentials;
    }
}
