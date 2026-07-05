namespace Picket.Security;

/// <summary>
/// Describes why an outbound endpoint was blocked.
/// </summary>
public enum EndpointGuardBlockReason
{
    /// <summary>
    /// The endpoint is allowed.
    /// </summary>
    None,

    /// <summary>
    /// The endpoint URI is not absolute.
    /// </summary>
    RelativeUri,

    /// <summary>
    /// The endpoint uses a non-HTTPS scheme while HTTPS is required.
    /// </summary>
    NonHttpsScheme,

    /// <summary>
    /// The endpoint host is a known metadata service host.
    /// </summary>
    MetadataHost,

    /// <summary>
    /// The endpoint host could not be resolved.
    /// </summary>
    DnsFailure,

    /// <summary>
    /// The endpoint resolved to a loopback, private, link-local, reserved, or otherwise non-public address.
    /// </summary>
    NonPublicAddress,
}
