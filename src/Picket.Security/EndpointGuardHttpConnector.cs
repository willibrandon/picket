using System.Net;
using System.Net.Sockets;

namespace Picket.Security;

internal sealed class EndpointGuardHttpConnector(
    EndpointGuardOptions endpointGuardOptions,
    Func<string, CancellationToken, ValueTask<IPAddress[]>>? addressResolver)
{
    private readonly EndpointGuardOptions _endpointGuardOptions = endpointGuardOptions ?? throw new ArgumentNullException(nameof(endpointGuardOptions));

    internal async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await ResolveAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new HttpRequestException("endpoint host could not be resolved", ex);
        }

        if (addresses is null)
        {
            throw new HttpRequestException("endpoint host did not resolve to an address");
        }

        EndpointGuardResult guardResult = EndpointGuard.Evaluate(CreateConnectedEndpoint(context), addresses, _endpointGuardOptions);
        if (!guardResult.IsAllowed)
        {
            throw new HttpRequestException(string.Concat("endpoint blocked: ", guardResult.BlockReason.ToString()));
        }

        return await ConnectToAllowedAddressAsync(context.DnsEndPoint, addresses, cancellationToken).ConfigureAwait(false);
    }

    private ValueTask<IPAddress[]> ResolveAddressesAsync(string host, CancellationToken cancellationToken)
    {
        return addressResolver is null
            ? new ValueTask<IPAddress[]>(Dns.GetHostAddressesAsync(host, cancellationToken))
            : addressResolver(host, cancellationToken);
    }

    private static Uri CreateConnectedEndpoint(SocketsHttpConnectionContext context)
    {
        string scheme = context.InitialRequestMessage.RequestUri?.Scheme ?? Uri.UriSchemeHttps;
        return new UriBuilder(scheme, context.DnsEndPoint.Host, context.DnsEndPoint.Port).Uri;
    }

    private static async ValueTask<Stream> ConnectToAllowedAddressAsync(
        DnsEndPoint endpoint,
        IPAddress[] addresses,
        CancellationToken cancellationToken)
    {
        SocketException? lastException = null;
        for (int i = 0; i < addresses.Length; i++)
        {
            var socket = new Socket(addresses[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(addresses[i], endpoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                lastException = ex;
                socket.Dispose();
            }
        }

        throw new HttpRequestException("endpoint connection failed", lastException);
    }
}
