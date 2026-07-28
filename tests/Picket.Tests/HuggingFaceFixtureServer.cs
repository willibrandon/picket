using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

internal sealed class HuggingFaceFixtureServer : IDisposable
{
    private readonly string _content;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal HuggingFaceFixtureServer(string content)
    {
        _content = content;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/");
        _serverTask = RunAsync(_shutdown.Token);
    }

    internal Uri Endpoint { get; }

    internal string LastAccept { get; private set; } = string.Empty;

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
        LastAccept = GetHeaderValue(request, "Accept");
        LastAuthorization = GetHeaderValue(request, "Authorization");
        lock (_requestTargetsLock)
        {
            _requestTargets.Add(target);
        }

        if (target.Equals(
            "/api/models/owner/project/revision/main",
            StringComparison.Ordinal))
        {
            await WriteResponseAsync(
                stream,
                "application/json",
                """{"sha":"abc123"}"""u8.ToArray(),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals(
            "/api/models/owner/project/tree/abc123?recursive=true&expand=true",
            StringComparison.Ordinal))
        {
            string json = string.Concat(
                "[{\"type\":\"file\",\"path\":\"secret.txt\",\"size\":",
                Encoding.UTF8.GetByteCount(_content).ToString(CultureInfo.InvariantCulture),
                "}]");
            await WriteResponseAsync(
                stream,
                "application/json",
                Encoding.UTF8.GetBytes(json),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals(
            "/owner/project/resolve/abc123/secret.txt",
            StringComparison.Ordinal))
        {
            await WriteResponseAsync(
                stream,
                "application/octet-stream",
                Encoding.UTF8.GetBytes(_content),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await WriteStatusAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadRequestAsync(
        NetworkStream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
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
        CancellationToken cancellationToken)
    {
        string headers = string.Concat(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: ",
            contentType,
            "\r\nContent-Length: ",
            content.Length.ToString(CultureInfo.InvariantCulture),
            "\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteStatusAsync(
        NetworkStream stream,
        int statusCode,
        string reasonPhrase,
        CancellationToken cancellationToken)
    {
        string headers = string.Concat(
            "HTTP/1.1 ",
            statusCode.ToString(CultureInfo.InvariantCulture),
            " ",
            reasonPhrase,
            "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), cancellationToken).ConfigureAwait(false);
    }
}
