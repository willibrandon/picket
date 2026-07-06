using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket;

internal sealed class CompatibilityDiagnosticsHttpServer : IDisposable
{
    private const int Port = 6060;
    private const int MaxRequestHeaderBytes = 8192;
    private readonly Func<string, CompatibilityDiagnosticsHttpResponse> _responseFactory;
    private readonly TcpListener _listener;
    private readonly Thread _thread;
    private bool _disposed;

    private CompatibilityDiagnosticsHttpServer(Func<string, CompatibilityDiagnosticsHttpResponse> responseFactory)
    {
        _responseFactory = responseFactory;
        _listener = new TcpListener(IPAddress.Loopback, Port);
        _listener.Start();
        _thread = new Thread(Listen)
        {
            IsBackground = true,
            Name = "picket-diagnostics-http"
        };
        _thread.Start();
    }

    internal static CompatibilityDiagnosticsHttpServer Start(Func<string, CompatibilityDiagnosticsHttpResponse> responseFactory)
    {
        ArgumentNullException.ThrowIfNull(responseFactory);
        return new CompatibilityDiagnosticsHttpServer(responseFactory);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _listener.Stop();
        if (!_thread.Join(TimeSpan.FromSeconds(1)))
        {
            _thread.Interrupt();
        }
    }

    private void Listen()
    {
        while (!_disposed)
        {
            try
            {
                using TcpClient client = _listener.AcceptTcpClient();
                Handle(client);
            }
            catch (SocketException) when (_disposed)
            {
                return;
            }
            catch (ObjectDisposedException) when (_disposed)
            {
                return;
            }
            catch (IOException)
            {
            }
            catch (InvalidOperationException) when (_disposed)
            {
                return;
            }
        }
    }

    private void Handle(TcpClient client)
    {
        client.ReceiveTimeout = 1000;
        client.SendTimeout = 1000;
        using NetworkStream stream = client.GetStream();
        string request = ReadRequest(stream);
        if (!TryParseRequest(request, out string method, out string path))
        {
            WriteResponse(stream, new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "bad request\n", 400), writeBody: true);
            return;
        }

        if (!method.Equals("GET", StringComparison.Ordinal) && !method.Equals("HEAD", StringComparison.Ordinal))
        {
            WriteResponse(stream, new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "method not allowed\n", 405), writeBody: true);
            return;
        }

        CompatibilityDiagnosticsHttpResponse response = _responseFactory(path);
        WriteResponse(stream, response, writeBody: method.Equals("GET", StringComparison.Ordinal));
    }

    private static string ReadRequest(NetworkStream stream)
    {
        Span<byte> single = stackalloc byte[1];
        byte[] bytes = new byte[MaxRequestHeaderBytes];
        int count = 0;
        while (count < bytes.Length)
        {
            int read = stream.Read(single);
            if (read == 0)
            {
                break;
            }

            bytes[count++] = single[0];
            if (count >= 4
                && bytes[count - 4] == '\r'
                && bytes[count - 3] == '\n'
                && bytes[count - 2] == '\r'
                && bytes[count - 1] == '\n')
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(bytes, 0, count);
    }

    private static bool TryParseRequest(string request, out string method, out string path)
    {
        method = string.Empty;
        path = string.Empty;
        int lineEnd = request.IndexOf("\r\n", StringComparison.Ordinal);
        string requestLine = lineEnd < 0 ? request : request[..lineEnd];
        string[] parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        method = parts[0];
        path = NormalizePath(parts[1]);
        return method.Length != 0 && path.Length != 0;
    }

    private static string NormalizePath(string value)
    {
        int queryIndex = value.IndexOf('?');
        if (queryIndex >= 0)
        {
            value = value[..queryIndex];
        }

        return value.Length == 0 ? "/" : value;
    }

    private static void WriteResponse(NetworkStream stream, CompatibilityDiagnosticsHttpResponse response, bool writeBody)
    {
        byte[] body = Encoding.UTF8.GetBytes(response.Body);
        string reason = GetReasonPhrase(response.StatusCode);
        var builder = new StringBuilder(256);
        builder.Append("HTTP/1.1 ");
        builder.Append(response.StatusCode.ToString(CultureInfo.InvariantCulture));
        builder.Append(' ');
        builder.Append(reason);
        builder.Append("\r\nContent-Type: ");
        builder.Append(response.ContentType);
        builder.Append("\r\nContent-Length: ");
        builder.Append((writeBody ? body.Length : 0).ToString(CultureInfo.InvariantCulture));
        builder.Append("\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
        byte[] header = Encoding.ASCII.GetBytes(builder.ToString());
        stream.Write(header);
        if (writeBody)
        {
            stream.Write(body);
        }
    }

    private static string GetReasonPhrase(int statusCode)
    {
        return statusCode switch
        {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "OK",
        };
    }
}
