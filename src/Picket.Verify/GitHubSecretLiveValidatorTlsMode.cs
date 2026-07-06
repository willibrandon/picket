namespace Picket.Verify;

/// <summary>
/// Defines TLS protocol selection for GitHub live validation requests.
/// </summary>
public enum GitHubSecretLiveValidatorTlsMode
{
    /// <summary>
    /// Uses the platform default TLS policy.
    /// </summary>
    System = 0,

    /// <summary>
    /// Allows TLS 1.2 or later for provider requests.
    /// </summary>
    Tls12OrLater = 1,
}
