namespace Picket.Verify;

/// <summary>
/// Describes the result of secret validation.
/// </summary>
public enum SecretValidationState
{
    /// <summary>
    /// The validator does not know how to validate the finding offline.
    /// </summary>
    Unknown,

    /// <summary>
    /// The finding matches a known provider structure, checksum, or envelope.
    /// </summary>
    StructurallyValid,

    /// <summary>
    /// The finding is a known dummy, sample, placeholder, or test credential.
    /// </summary>
    TestCredential,

    /// <summary>
    /// The finding failed a known offline provider structure or checksum check.
    /// </summary>
    Invalid,

    /// <summary>
    /// Live provider verification proved the credential is active.
    /// </summary>
    Active,

    /// <summary>
    /// Live provider verification proved the credential is inactive or revoked.
    /// </summary>
    Inactive,

    /// <summary>
    /// Live provider verification intentionally skipped the finding.
    /// </summary>
    Skipped,

    /// <summary>
    /// Live provider verification failed with a provider, network, policy, or rate-limit error.
    /// </summary>
    Error,
}
