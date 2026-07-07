namespace Picket.Security;

/// <summary>
/// Creates HTTP handlers that enforce endpoint guard checks against the address used for each socket connection.
/// </summary>
public static class EndpointGuardHttpHandlerFactory
{
    /// <summary>
    /// Creates a sockets-based HTTP handler with redirects disabled and connect-time endpoint checks enabled.
    /// </summary>
    /// <param name="options">The guarded HTTP handler options, or <see langword="null" /> for defaults.</param>
    /// <returns>A configured <see cref="SocketsHttpHandler" />.</returns>
    public static SocketsHttpHandler Create(EndpointGuardHttpHandlerOptions? options = null)
    {
        EndpointGuardHttpHandlerOptions resolvedOptions = options ?? new EndpointGuardHttpHandlerOptions();
        var connector = new EndpointGuardHttpConnector(resolvedOptions.EndpointGuardOptions, resolvedOptions.AddressResolver);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = connector.ConnectAsync,
        };

        handler.SslOptions.EnabledSslProtocols = resolvedOptions.EnabledSslProtocols;
        if (resolvedOptions.Proxy is not null)
        {
            handler.Proxy = resolvedOptions.Proxy;
            handler.UseProxy = true;
        }

        return handler;
    }
}
