using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

internal sealed class ContainerRegistryFixtureServer : IDisposable
{
    internal const string BearerToken = "registry-fixture-token";

    private readonly byte[] _configContent;
    private readonly string _configDigest;
    private readonly byte[] _layerContent;
    private readonly string _layerDigest;
    private readonly byte[] _manifestContent;
    private readonly string _manifestDigest;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal ContainerRegistryFixtureServer(string content)
    {
        _configContent = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        _configDigest = CreateDigest(_configContent);
        byte[] layerTar = TarTestData.CreateTarBytes(("app/settings.txt", Encoding.UTF8.GetBytes(content)));
        _layerContent = TarTestData.CreateGzipBytes(layerTar);
        _layerDigest = CreateDigest(_layerContent);
        _manifestContent = Encoding.UTF8.GetBytes($$"""
            {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{_configDigest}}","size":{{_configContent.Length}}},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{{_layerDigest}}","size":{{_layerContent.Length}}}]}
            """);
        _manifestDigest = CreateDigest(_manifestContent);

        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/");
        _serverTask = RunAsync(_shutdown.Token);
    }

    internal Uri Endpoint { get; }

    internal string LastAuthorization { get; private set; } = string.Empty;

    internal string RequestTargets
    {
        get
        {
            lock (_requestTargetsLock)
            {
                return string.Join('\n', _requestTargets);
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _shutdown.Cancel();
        _listener.Stop();
        try
        {
            _serverTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }

        _shutdown.Dispose();
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            await HandleAsync(client, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken cancellationToken)
    {
        NetworkStream stream = client.GetStream();
        string request = await ReadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
        string target = GetRequestTarget(request);
        LastAuthorization = GetHeaderValue(request, "Authorization");
        lock (_requestTargetsLock)
        {
            _requestTargets.Add(target);
        }

        if (target.StartsWith("/token?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(
                stream,
                "application/json",
                Encoding.UTF8.GetBytes($$"""{"token":"{{BearerToken}}"}"""),
                digest: null,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/v2/team/image/manifests/latest", StringComparison.Ordinal))
        {
            if (!LastAuthorization.Equals($"Bearer {BearerToken}", StringComparison.Ordinal))
            {
                string challenge = $"Bearer realm=\"{new Uri(Endpoint, "token").AbsoluteUri}\",service=\"registry-fixture\",scope=\"repository:team/image:pull\"";
                await WriteUnauthorizedAsync(stream, challenge, cancellationToken).ConfigureAwait(false);
                return;
            }

            await WriteResponseAsync(
                stream,
                "application/vnd.oci.image.manifest.v1+json",
                _manifestContent,
                _manifestDigest,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals($"/v2/team/image/blobs/{_configDigest}", StringComparison.Ordinal))
        {
            await WriteResponseAsync(
                stream,
                "application/octet-stream",
                _configContent,
                _configDigest,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals($"/v2/team/image/blobs/{_layerDigest}", StringComparison.Ordinal))
        {
            await WriteResponseAsync(
                stream,
                "application/octet-stream",
                _layerContent,
                _layerDigest,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await WriteNotFoundAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[1024];
        var builder = new StringBuilder();
        while (!builder.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
        {
            int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            builder.Append(Encoding.ASCII.GetString(buffer, 0, read));
        }

        return builder.ToString();
    }

    private static string GetRequestTarget(string request)
    {
        int firstSpace = request.IndexOf(' ', StringComparison.Ordinal);
        if (firstSpace < 0)
        {
            return string.Empty;
        }

        int secondSpace = request.IndexOf(' ', firstSpace + 1);
        return secondSpace < 0 ? string.Empty : request[(firstSpace + 1)..secondSpace];
    }

    private static string GetHeaderValue(string request, string headerName)
    {
        string prefix = string.Concat(headerName, ":");
        foreach (string line in request.Split("\r\n"))
        {
            if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return line[prefix.Length..].Trim();
            }
        }

        return string.Empty;
    }

    private static async Task WriteResponseAsync(
        NetworkStream stream,
        string contentType,
        byte[] content,
        string? digest,
        CancellationToken cancellationToken)
    {
        var header = new StringBuilder();
        header.Append("HTTP/1.1 200 OK\r\nContent-Type: ");
        header.Append(contentType);
        header.Append("\r\nContent-Length: ");
        header.Append(content.Length);
        if (digest is not null)
        {
            header.Append("\r\nDocker-Content-Digest: ");
            header.Append(digest);
        }

        header.Append("\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(header.ToString()), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteUnauthorizedAsync(
        NetworkStream stream,
        string challenge,
        CancellationToken cancellationToken)
    {
        string response = string.Concat(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: ",
            challenge,
            "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteNotFoundAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        const string Response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(Response), cancellationToken).ConfigureAwait(false);
    }

    private static string CreateDigest(byte[] content)
    {
        return string.Concat("sha256:", Convert.ToHexStringLower(SHA256.HashData(content)));
    }
}
