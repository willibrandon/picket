using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

internal sealed class GitHubFixtureServer : IDisposable
{
    private readonly string _content;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal GitHubFixtureServer(string content)
    {
        _content = content;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/api/v3/");
        _serverTask = RunAsync(_shutdown.Token);
    }

    internal Uri Endpoint { get; }

    internal string LastAuthorization { get; private set; } = string.Empty;

    internal string LastAccept { get; private set; } = string.Empty;

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
        lock (_requestTargetsLock)
        {
            _requestTargets.Add(target);
        }

        if (target.Contains("/api/v3/orgs/willibrandon/repos?", StringComparison.Ordinal))
        {
            const string RepositoriesJson = """[{"name":"picket","default_branch":"main"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoriesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/users/octocat/repos?", StringComparison.Ordinal))
        {
            const string RepositoriesJson = """[{"name":"hello","full_name":"octocat/hello","default_branch":"main"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoriesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/pulls/42", StringComparison.Ordinal))
        {
            const string PullRequestJson = """{"number":42,"head":{"sha":"abcdef1234567890","repo":{"full_name":"forker/picket-fork"}}}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(PullRequestJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/forker/picket-fork/contents/src/appsettings.txt?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/forker/picket-fork/git/trees/abcdef1234567890?", StringComparison.Ordinal))
        {
            const string TreeJson = """{"tree":[{"path":"src/appsettings.txt","type":"blob","size":11}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/issues/7/comments?", StringComparison.Ordinal))
        {
            const string CommentsJson = """[{"id":99,"body":"comment-token-888"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(CommentsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/issues?", StringComparison.Ordinal))
        {
            const string IssuesJson = """[{"number":7,"title":"leaked issue-token-777","body":"body-token-777","comments":1},{"number":8,"title":"pull request token-999","body":"skip-token-999","comments":1,"pull_request":{"url":"https://api.github.com/repos/willibrandon/picket/pulls/8"}}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(IssuesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/gists/auth-gist/comments?", StringComparison.Ordinal))
        {
            const string CommentsJson = """[{"id":77,"body":"comment-token-999"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(CommentsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/raw/gists/auth-gist/raw.txt", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes("raw-token-777"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/gists/auth-gist", StringComparison.Ordinal))
        {
            string rawUrl = string.Concat(Endpoint.GetLeftPart(UriPartial.Authority), "/raw/gists/auth-gist/raw.txt");
            string gistJson = string.Concat(
                "{\"id\":\"auth-gist\",\"owner\":{\"login\":\"willibrandon\"},\"comments\":1,\"files\":{\"secret.txt\":{\"filename\":\"secret.txt\",\"size\":",
                _content.Length.ToString(CultureInfo.InvariantCulture),
                ",\"truncated\":false,\"content\":\"",
                _content,
                "\"},\"raw.txt\":{\"filename\":\"raw.txt\",\"size\":13,\"truncated\":true,\"raw_url\":\"",
                rawUrl,
                "\"}}}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(gistJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/gists?", StringComparison.Ordinal))
        {
            const string GistsJson = """[{"id":"auth-gist"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(GistsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/releases/assets/501", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes("asset-token-555"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/releases?", StringComparison.Ordinal))
        {
            string assetUrl = string.Concat(Endpoint.AbsoluteUri, "repos/willibrandon/picket/releases/assets/501");
            string releasesJson = string.Concat(
                "[{\"id\":100,\"tag_name\":\"v1.0.0\",\"name\":\"Release token-444\",\"body\":\"body-token-444\",\"assets\":[{\"id\":501,\"name\":\"artifact.txt\",\"size\":15,\"url\":\"",
                assetUrl,
                "\"}]}]");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(releasesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/actions/artifacts/701/zip", StringComparison.Ordinal))
        {
            byte[] archiveBytes = CreateZipBytes(("nested/secret.txt", Encoding.UTF8.GetBytes("artifact-token-666")));
            await WriteResponseAsync(stream, "application/zip", archiveBytes, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/actions/artifacts?", StringComparison.Ordinal))
        {
            string archiveUrl = string.Concat(Endpoint.AbsoluteUri, "repos/willibrandon/picket/actions/artifacts/701/zip");
            string artifactsJson = string.Concat(
                "{\"total_count\":1,\"artifacts\":[{\"id\":701,\"name\":\"build\",\"size_in_bytes\":160,\"expired\":false,\"archive_download_url\":\"",
                archiveUrl,
                "\"}]}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(artifactsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/contents/src/appsettings.txt?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/octocat/hello/contents/src/appsettings.txt?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket/git/trees/main?", StringComparison.Ordinal))
        {
            const string TreeJson = """{"tree":[{"path":"src/appsettings.txt","type":"blob","size":11}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/octocat/hello/git/trees/main?", StringComparison.Ordinal))
        {
            const string TreeJson = """{"tree":[{"path":"src/appsettings.txt","type":"blob","size":11}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(TreeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/api/v3/repos/willibrandon/picket", StringComparison.Ordinal))
        {
            const string RepositoryJson = """{"default_branch":"main"}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoryJson), cancellationToken).ConfigureAwait(false);
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

    private static byte[] CreateZipBytes(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using Stream entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        return stream.ToArray();
    }
}
