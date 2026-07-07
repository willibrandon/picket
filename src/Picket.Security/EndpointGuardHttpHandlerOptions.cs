using System.Net;
using System.Security.Authentication;

namespace Picket.Security;

/// <summary>
/// Configures a guarded HTTP handler created by the endpoint guard HTTP handler factory.
/// </summary>
public sealed class EndpointGuardHttpHandlerOptions
{
    private EndpointGuardOptions _endpointGuardOptions = EndpointGuardOptions.CreateDefault();

    /// <summary>
    /// Gets or sets the endpoint guard options applied to the actual connected address.
    /// </summary>
    public EndpointGuardOptions EndpointGuardOptions
    {
        get => _endpointGuardOptions;
        set => _endpointGuardOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the optional address resolver used before connecting a socket.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<IPAddress[]>>? AddressResolver { get; set; }

    /// <summary>
    /// Gets or sets the TLS protocols enabled for HTTPS connections.
    /// </summary>
    public SslProtocols EnabledSslProtocols { get; set; } = SslProtocols.None;

    /// <summary>
    /// Gets or sets the optional proxy used by the handler.
    /// </summary>
    public IWebProxy? Proxy { get; set; }
}
