using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

internal sealed class GitLabFixtureServer : IDisposable
{
    private readonly string _content;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal GitLabFixtureServer(string content)
    {
        _content = content;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/api/v4/");
        _serverTask = RunAsync(_shutdown.Token);
    }

    internal Uri Endpoint { get; }

    internal string LastAuthorization { get; private set; } = string.Empty;

    internal string LastAccept { get; private set; } = string.Empty;

    internal string LastPrivateToken { get; private set; } = string.Empty;

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
        LastAccept = GetHeaderValue(request, "Accept");
        LastPrivateToken = GetHeaderValue(request, "PRIVATE-TOKEN");
        lock (_requestTargetsLock)
        {
            _requestTargets.Add(target);
        }

        if (target.Contains("/api/v4/projects/123/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/team%2Fplatform%2Fapi/repository/files/src%2Fappsettings.txt/raw?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/snippets/7/raw", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/snippets?", StringComparison.Ordinal))
        {
            const string SnippetsJson = """[{"id":7,"file_name":"ops/token.txt","raw_url":"https://gitlab.example/snippets/7/raw"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(SnippetsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/trace", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs/99/artifacts", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", CreateZipBytes("out/secret.txt", _content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/jobs?", StringComparison.Ordinal))
        {
            const string JobsJson = """[{"id":99,"name":"build","artifacts_file":{"filename":"artifacts.zip","size":128}}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(JobsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/123/repository/tree?", StringComparison.Ordinal))
        {
            const string TreeJson = """[{"path":"src/appsettings.txt","type":"blob","size":11},{"path":"src","type":"tree"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/repository/tree?", StringComparison.Ordinal))
        {
            const string TreeJson = """[{"path":"src/appsettings.txt","type":"blob","size":11},{"path":"src","type":"tree"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/team%2Fplatform%2Fapi/repository/tree?", StringComparison.Ordinal))
        {
            const string TreeJson = """[{"path":"src/appsettings.txt","type":"blob","size":11},{"path":"src","type":"tree"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/groups/team%2Fplatform/projects?", StringComparison.Ordinal))
        {
            const string GroupProjectsJson = """[{"id":321,"path_with_namespace":"team/platform/api","default_branch":"main"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(GroupProjectsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket/merge_requests/42", StringComparison.Ordinal))
        {
            const string MergeRequestJson = """
                {"iid":42,"source_project_id":123,"target_project_id":456,"source_branch":"feature/scan","sha":"sha-from-merge-request","diff_refs":{"head_sha":"abcdef1234567890"}}
                """;
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(MergeRequestJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v4/projects/willibrandon%2Fpicket", StringComparison.Ordinal))
        {
            const string ProjectJson = """{"default_branch":"main"}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(ProjectJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        await WriteStatusAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
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
            content.Length.ToString(),
            "\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] CreateZipBytes(string entryName, string entryContent)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using Stream entryStream = entry.Open();
            byte[] bytes = Encoding.UTF8.GetBytes(entryContent);
            entryStream.Write(bytes);
        }

        return stream.ToArray();
    }

    private static async Task WriteStatusAsync(
        NetworkStream stream,
        int statusCode,
        string reasonPhrase,
        CancellationToken cancellationToken)
    {
        string headers = string.Concat(
            "HTTP/1.1 ",
            statusCode.ToString(),
            " ",
            reasonPhrase,
            "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), cancellationToken).ConfigureAwait(false);
    }
}
