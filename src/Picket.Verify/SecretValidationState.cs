namespace Picket.Verify;

/// <summary>
/// Describes the result of offline secret validation.
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
}
