using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

internal sealed class GiteaFixtureServer : IDisposable
{
    private readonly string _content;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal GiteaFixtureServer(string content)
    {
        _content = content;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/api/v1/");
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

        if (target.Equals("/api/v1/repos/willibrandon/picket", StringComparison.Ordinal))
        {
            const string RepositoryJson = """{"default_branch":"main","empty":false}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoryJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/api/v1/repos/willibrandon/picket/branches/main", StringComparison.Ordinal))
        {
            const string BranchJson = """{"name":"main","commit":{"id":"abcdef1234567890"}}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(BranchJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/orgs/willibrandon/repos?", StringComparison.Ordinal)
            || target.StartsWith("/api/v1/users/willibrandon/repos?", StringComparison.Ordinal))
        {
            const string RepositoriesJson = """[{"full_name":"willibrandon/picket","name":"picket","default_branch":"main"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoriesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/api/v1/repos/willibrandon/picket/pulls/7", StringComparison.Ordinal))
        {
            const string PullRequestJson = """{"number":7,"head":{"sha":"pr-head-sha","ref":"feature/secrets","repo":{"full_name":"forker/picket-fork"}}}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(PullRequestJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/repos/willibrandon/picket/git/trees/abcdef1234567890?", StringComparison.Ordinal))
        {
            string treeJson = string.Concat(
                "{\"tree\":[{\"path\":\"src/appsettings.txt\",\"type\":\"blob\",\"size\":",
                Encoding.UTF8.GetByteCount(_content).ToString(CultureInfo.InvariantCulture),
                "},{\"path\":\"src\",\"type\":\"tree\"}],\"truncated\":false,\"page\":1,\"total_count\":2}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(treeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/repos/forker/picket-fork/git/trees/pr-head-sha?", StringComparison.Ordinal))
        {
            string treeJson = string.Concat(
                "{\"tree\":[{\"path\":\"src/pr.txt\",\"type\":\"blob\",\"size\":",
                Encoding.UTF8.GetByteCount(_content).ToString(CultureInfo.InvariantCulture),
                "}],\"truncated\":false,\"page\":1,\"total_count\":1}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(treeJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/repos/willibrandon/picket/issues/comments?", StringComparison.Ordinal))
        {
            const string IssueCommentsJson = """[{"id":99,"issue_url":"http://127.0.0.1/api/v1/repos/willibrandon/picket/issues/7","body":"comment-token-222"},{"id":100,"issue_url":"http://127.0.0.1/api/v1/repos/willibrandon/picket/issues/8","body":"skip-token-999"}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(IssueCommentsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/repos/willibrandon/picket/issues?", StringComparison.Ordinal))
        {
            const string IssuesJson = """[{"number":7,"title":"leaked issue-token-111","body":"body-token-111","comments":1},{"number":8,"title":"pull request token-999","body":"skip-token-999","comments":1,"pull_request":{"url":"http://127.0.0.1/api/v1/repos/willibrandon/picket/pulls/8"}}]""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(IssuesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.StartsWith("/api/v1/repos/willibrandon/picket/releases?", StringComparison.Ordinal))
        {
            string releasesJson = string.Concat(
                "[{\"id\":100,\"tag_name\":\"v1.0.0\",\"name\":\"Release token-111\",\"body\":\"body-token-111\",\"assets\":[{\"id\":501,\"name\":\"artifact.txt\",\"size\":15,\"browser_download_url\":\"",
                Endpoint.GetLeftPart(UriPartial.Authority),
                "/downloads/artifact.txt\"}]}]");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(releasesJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/downloads/artifact.txt", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes("asset-token-222"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/api/packages/willibrandon/generic/picket-cli/1.0.0/secrets.txt", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/api/v1/repos/willibrandon/picket/raw/src/appsettings.txt?ref=main", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Equals("/api/v1/repos/forker/picket-fork/raw/src/pr.txt?ref=pr-head-sha", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
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
