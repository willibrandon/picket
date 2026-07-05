namespace Picket.Security;

/// <summary>
/// Configures outbound endpoint safety checks.
/// </summary>
public sealed class EndpointGuardOptions
{
    /// <summary>
    /// Creates default endpoint guard options for live verification.
    /// </summary>
    /// <returns>Default endpoint guard options.</returns>
    public static EndpointGuardOptions CreateDefault()
    {
        return new EndpointGuardOptions();
    }

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS is required.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether loopback, private, link-local, reserved, and other non-public addresses are allowed.
    /// </summary>
    public bool AllowNonPublicAddresses { get; set; }
}
