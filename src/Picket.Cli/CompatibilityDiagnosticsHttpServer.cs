using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Picket;

internal sealed class CompatibilityDiagnosticsHttpServer : IDisposable
{
    private const int MaxRequestHeaderBytes = 8192;
    private const int TokenByteLength = 16;
    private readonly Func<string, CompatibilityDiagnosticsHttpResponse> _responseFactory;
    private readonly TcpListener _listener;
    private readonly Thread _thread;
    private readonly string _token;
    private bool _disposed;

    private CompatibilityDiagnosticsHttpServer(Func<string, CompatibilityDiagnosticsHttpResponse> responseFactory)
    {
        _responseFactory = responseFactory;
        _token = CreateToken();
        _listener = new TcpListener(IPAddress.Loopback, port: 0);
        _listener.Start();
        var endpoint = (IPEndPoint)_listener.LocalEndpoint;
        AuthenticationQueryString = $"token={_token}";
        DiagnosticsUri = $"http://127.0.0.1:{endpoint.Port.ToString(CultureInfo.InvariantCulture)}/debug/pprof/?{AuthenticationQueryString}";
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

    internal string DiagnosticsUri { get; }

    internal string AuthenticationQueryString { get; }

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
                TcpClient client = _listener.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(_ => HandleClient(client));
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

    private void HandleClient(TcpClient client)
    {
        using (client)
        {
            try
            {
                Handle(client);
            }
            catch (IOException)
            {
            }
            catch (ObjectDisposedException) when (_disposed)
            {
            }
            catch (SocketException) when (_disposed)
            {
            }
        }
    }

    private void Handle(TcpClient client)
    {
        client.ReceiveTimeout = 1000;
        client.SendTimeout = 1000;
        using NetworkStream stream = client.GetStream();
        string request = ReadRequest(stream);
        if (!TryParseRequest(request, out string method, out string path, out string token))
        {
            WriteResponse(stream, new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "bad request\n", 400), writeBody: true);
            return;
        }

        if (!IsAuthorized(token))
        {
            WriteResponse(stream, new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "unauthorized\n", 401), writeBody: true);
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

    private static bool TryParseRequest(string request, out string method, out string path, out string token)
    {
        method = string.Empty;
        path = string.Empty;
        token = string.Empty;
        int lineEnd = request.IndexOf("\r\n", StringComparison.Ordinal);
        string requestLine = lineEnd < 0 ? request : request[..lineEnd];
        string[] parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        method = parts[0];
        path = NormalizePath(parts[1], out token);
        return method.Length != 0 && path.Length != 0;
    }

    private static string NormalizePath(string value, out string token)
    {
        token = string.Empty;
        int queryIndex = value.IndexOf('?');
        if (queryIndex >= 0)
        {
            token = ExtractToken(value[(queryIndex + 1)..]);
            value = value[..queryIndex];
        }

        return value.Length == 0 ? "/" : value;
    }

    private bool IsAuthorized(string token)
    {
        return token.Length == _token.Length
            && CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(token),
                Encoding.ASCII.GetBytes(_token));
    }

    private static string ExtractToken(string query)
    {
        string[] parameters = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parameters.Length; i++)
        {
            string parameter = parameters[i];
            int separator = parameter.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            if (parameter[..separator].Equals("token", StringComparison.Ordinal))
            {
                return parameter[(separator + 1)..];
            }
        }

        return string.Empty;
    }

    private static string CreateToken()
    {
        return Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(TokenByteLength));
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
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "OK",
        };
    }
}
