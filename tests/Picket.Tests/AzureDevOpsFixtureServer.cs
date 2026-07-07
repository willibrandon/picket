using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Picket.Tests;

internal sealed class AzureDevOpsFixtureServer : IDisposable
{
    private readonly string _content;
    private readonly List<string> _requestTargets = [];
    private readonly Lock _requestTargetsLock = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TcpListener _listener;
    private readonly Task _serverTask;

    internal AzureDevOpsFixtureServer(string content)
    {
        _content = content;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri($"http://127.0.0.1:{port}/willibrandon/");
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

        if (target.Contains("/_apis/git/repositories/repo-id/pullRequests/42?", StringComparison.Ordinal))
        {
            const string PullRequestJson = """{"pullRequestId":42,"sourceRefName":"refs/heads/feature/secret","lastMergeSourceCommit":{"commitId":"abcdef1234567890"}}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(PullRequestJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/git/repositories/wiki-repo/items?", StringComparison.Ordinal)
            && target.Contains("download=true", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes("wiki-token-6789"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/git/repositories/wiki-repo/items?", StringComparison.Ordinal))
        {
            const string WikiItemsJson = """{"value":[{"path":"/Home.md","gitObjectType":"blob"}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(WikiItemsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/wiki/wikis?", StringComparison.Ordinal))
        {
            const string WikisJson = """{"value":[{"id":"wiki-id","name":"Team Wiki","projectId":"test","repositoryId":"wiki-repo","mappedPath":"/","versions":[{"version":"wikiMaster"}]}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(WikisJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal)
            && target.Contains("artifactName=drop", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/zip", CreateZipBytes("nested/artifact.txt", "artifact-token-2468"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/77/artifacts?", StringComparison.Ordinal))
        {
            string artifactsJson = string.Concat(
                "{\"value\":[{\"id\":12,\"name\":\"drop\",\"resource\":{\"downloadUrl\":\"",
                Endpoint.AbsoluteUri,
                "test/_apis/build/builds/77/artifacts?artifactName=drop&api-version=7.1",
                "\"}}]}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(artifactsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/77/logs/4?", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "text/plain", Encoding.UTF8.GetBytes("log-token-1357"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/77/logs?", StringComparison.Ordinal))
        {
            const string LogsJson = """{"value":[{"id":4,"type":"container","url":"https://dev.azure.com/willibrandon/test/_apis/build/builds/77/logs/4"}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(LogsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/release/releases/88?", StringComparison.Ordinal))
        {
            const string ReleaseJson = """
                {"id":88,"artifacts":[{"alias":"release-drop","type":"Build","definitionReference":{"version":{"id":"99"},"project":{"name":"test"}}}]}
                """;
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(ReleaseJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/99/artifacts?", StringComparison.Ordinal)
            && target.Contains("artifactName=release-drop", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/zip", CreateZipBytes("release/artifact.txt", "release-token-8642"), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/build/builds/99/artifacts?", StringComparison.Ordinal))
        {
            string artifactsJson = string.Concat(
                "{\"value\":[{\"id\":13,\"name\":\"release-drop\",\"resource\":{\"downloadUrl\":\"",
                Endpoint.AbsoluteUri,
                "test/_apis/build/builds/99/artifacts?artifactName=release-drop&api-version=7.1",
                "\"}}]}");
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(artifactsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/git/repositories/repo-id/items?", StringComparison.Ordinal)
            && target.Contains("download=true", StringComparison.Ordinal))
        {
            await WriteResponseAsync(stream, "application/octet-stream", Encoding.UTF8.GetBytes(_content), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/git/repositories/repo-id/items?", StringComparison.Ordinal))
        {
            const string ItemsJson = """{"value":[{"path":"/src/appsettings.txt","gitObjectType":"blob"}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(ItemsJson), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (target.Contains("/_apis/git/repositories?", StringComparison.Ordinal))
        {
            const string RepositoriesJson = """{"value":[{"id":"repo-id","name":"picket","project":{"name":"test"}}]}""";
            await WriteResponseAsync(stream, "application/json", Encoding.UTF8.GetBytes(RepositoriesJson), cancellationToken).ConfigureAwait(false);
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

    private static byte[] CreateZipBytes(string entryName, string content)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using Stream entryStream = entry.Open();
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            entryStream.Write(bytes);
        }

        return stream.ToArray();
    }
}
