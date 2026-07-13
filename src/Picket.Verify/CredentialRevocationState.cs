namespace Picket.Verify;

/// <summary>
/// Describes the outcome of an explicit credential revocation request.
/// </summary>
public enum CredentialRevocationState
{
    /// <summary>
    /// The provider outcome is unknown because the request did not produce a conclusive response.
    /// </summary>
    Indeterminate = 0,

    /// <summary>
    /// The provider accepted the credential revocation request.
    /// </summary>
    Accepted = 1,

    /// <summary>
    /// The provider rejected the credential revocation request.
    /// </summary>
    Rejected = 2,

    /// <summary>
    /// Picket blocked the request before it could be sent or followed.
    /// </summary>
    Blocked = 3,
}
