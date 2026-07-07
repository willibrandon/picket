using System.Net;
using System.Net.Sockets;

namespace Picket.Security;

/// <summary>
/// Validates outbound provider endpoints before live verification or analysis can contact them.
/// </summary>
public static class EndpointGuard
{
    private static readonly string[] s_metadataHosts =
    [
        "169.254.169.254",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "metadata.oraclecloud.com",
        "100.100.100.200",
    ];

    /// <summary>
    /// Evaluates an endpoint by resolving its host with the platform DNS resolver.
    /// </summary>
    /// <param name="endpoint">The endpoint URI to evaluate.</param>
    /// <param name="options">The guard options, or <see langword="null" /> to use defaults.</param>
    /// <returns>The endpoint safety decision.</returns>
    public static EndpointGuardResult Evaluate(Uri endpoint, EndpointGuardOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        EndpointGuardResult uriResult = EvaluateUri(endpoint, options);
        if (!uriResult.IsAllowed)
        {
            return uriResult;
        }

        try
        {
            return Evaluate(endpoint, Dns.GetHostAddresses(endpoint.DnsSafeHost), options);
        }
        catch (SocketException)
        {
            return EndpointGuardResult.Block(EndpointGuardBlockReason.DnsFailure, "endpoint host could not be resolved");
        }
    }

    /// <summary>
    /// Evaluates an endpoint with caller-supplied resolved addresses.
    /// </summary>
    /// <param name="endpoint">The endpoint URI to evaluate.</param>
    /// <param name="resolvedAddresses">The resolved endpoint addresses.</param>
    /// <param name="options">The guard options, or <see langword="null" /> to use defaults.</param>
    /// <returns>The endpoint safety decision.</returns>
    public static EndpointGuardResult Evaluate(Uri endpoint, IReadOnlyList<IPAddress> resolvedAddresses, EndpointGuardOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(resolvedAddresses);

        EndpointGuardOptions resolvedOptions = options ?? EndpointGuardOptions.CreateDefault();
        EndpointGuardResult uriResult = EvaluateUri(endpoint, resolvedOptions);
        if (!uriResult.IsAllowed)
        {
            return uriResult;
        }

        if (resolvedAddresses.Count == 0)
        {
            return EndpointGuardResult.Block(EndpointGuardBlockReason.DnsFailure, "endpoint host did not resolve to an address");
        }

        if (resolvedOptions.AllowNonPublicAddresses)
        {
            return EndpointGuardResult.Allow();
        }

        for (int i = 0; i < resolvedAddresses.Count; i++)
        {
            if (IsNonPublicAddress(resolvedAddresses[i]))
            {
                return EndpointGuardResult.Block(EndpointGuardBlockReason.NonPublicAddress, "endpoint resolves to a non-public address");
            }
        }

        return EndpointGuardResult.Allow();
    }

    /// <summary>
    /// Returns a value indicating whether an IP address is non-public for outbound verification purposes.
    /// </summary>
    /// <param name="address">The IP address to classify.</param>
    /// <returns><see langword="true" /> when the address is loopback, private, link-local, reserved, or otherwise non-public.</returns>
    public static bool IsNonPublicAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.None)
            || address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsNonPublicIPv4(address.GetAddressBytes()),
            AddressFamily.InterNetworkV6 => IsNonPublicIPv6(address.GetAddressBytes()),
            _ => true,
        };
    }

    private static EndpointGuardResult EvaluateUri(Uri endpoint, EndpointGuardOptions? options)
    {
        EndpointGuardOptions resolvedOptions = options ?? EndpointGuardOptions.CreateDefault();
        if (!endpoint.IsAbsoluteUri)
        {
            return EndpointGuardResult.Block(EndpointGuardBlockReason.RelativeUri, "endpoint URI must be absolute");
        }

        if (resolvedOptions.RequireHttps && !endpoint.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return EndpointGuardResult.Block(EndpointGuardBlockReason.NonHttpsScheme, "endpoint URI must use HTTPS");
        }

        if (IsMetadataHost(endpoint.DnsSafeHost))
        {
            return EndpointGuardResult.Block(EndpointGuardBlockReason.MetadataHost, "endpoint host is a metadata service");
        }

        return EndpointGuardResult.Allow();
    }

    private static bool IsMetadataHost(string host)
    {
        host = host.TrimEnd('.');
        for (int i = 0; i < s_metadataHosts.Length; i++)
        {
            if (host.Equals(s_metadataHosts[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNonPublicIPv4(ReadOnlySpan<byte> bytes)
    {
        return bytes[0] switch
        {
            0 => true,
            10 => true,
            100 when bytes[1] is >= 64 and <= 127 => true,
            127 => true,
            169 when bytes[1] == 254 => true,
            172 when bytes[1] is >= 16 and <= 31 => true,
            192 when bytes[1] == 0 && bytes[2] == 0 => true,
            192 when bytes[1] == 0 && bytes[2] == 2 => true,
            192 when bytes[1] == 168 => true,
            198 when bytes[1] is 18 or 19 => true,
            198 when bytes[1] == 51 && bytes[2] == 100 => true,
            203 when bytes[1] == 0 && bytes[2] == 113 => true,
            >= 224 => true,
            _ => false,
        };
    }

    private static bool IsNonPublicIPv6(byte[] bytes)
    {
        return (bytes[0] & 0xFE) == 0xFC
            || bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
            || bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0
            || bytes[0] == 0xFF
            || IsIPv6DocumentationAddress(bytes)
            || IsIPv4MappedNonPublicAddress(bytes)
            || IsIPv4CompatibleNonPublicAddress(bytes)
            || IsNat64NonPublicAddress(bytes)
            || Is6To4NonPublicAddress(bytes)
            || IsTeredoNonPublicAddress(bytes);
    }

    private static bool IsIPv6DocumentationAddress(byte[] bytes)
    {
        return bytes[0] == 0x20
            && bytes[1] == 0x01
            && bytes[2] == 0x0D
            && bytes[3] == 0xB8;
    }

    private static bool IsIPv4MappedNonPublicAddress(byte[] bytes)
    {
        for (int i = 0; i < 10; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        return bytes[10] == 0xFF
            && bytes[11] == 0xFF
            && IsNonPublicIPv4(bytes.AsSpan(12, 4));
    }

    private static bool IsIPv4CompatibleNonPublicAddress(byte[] bytes)
    {
        for (int i = 0; i < 12; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        return IsNonPublicIPv4(bytes.AsSpan(12, 4));
    }

    private static bool IsNat64NonPublicAddress(byte[] bytes)
    {
        if (bytes[0] != 0x00
            || bytes[1] != 0x64
            || bytes[2] != 0xFF
            || bytes[3] != 0x9B)
        {
            return false;
        }

        for (int i = 4; i < 12; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        return IsNonPublicIPv4(bytes.AsSpan(12, 4));
    }

    private static bool Is6To4NonPublicAddress(byte[] bytes)
    {
        return bytes[0] == 0x20
            && bytes[1] == 0x02
            && IsNonPublicIPv4(bytes.AsSpan(2, 4));
    }

    private static bool IsTeredoNonPublicAddress(byte[] bytes)
    {
        if (bytes[0] != 0x20
            || bytes[1] != 0x01
            || bytes[2] != 0x00
            || bytes[3] != 0x00)
        {
            return false;
        }

        Span<byte> clientAddress = stackalloc byte[4];
        clientAddress[0] = (byte)~bytes[12];
        clientAddress[1] = (byte)~bytes[13];
        clientAddress[2] = (byte)~bytes[14];
        clientAddress[3] = (byte)~bytes[15];
        return IsNonPublicIPv4(clientAddress);
    }
}
