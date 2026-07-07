using Picket.Security;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Picket.Verify;

/// <summary>
/// Configures GitHub live secret verification.
/// </summary>
public sealed class GitHubSecretLiveValidatorOptions
{
    private const int DefaultMaxResponseBytes = 65_536;

    private EndpointGuardOptions _endpointGuardOptions = EndpointGuardOptions.CreateDefault();
    private Func<string, CancellationToken, ValueTask<IPAddress[]>>? _addressResolver;
    private Func<HttpMessageHandler>? _messageHandlerFactory;
    private int _maxResponseBytes = DefaultMaxResponseBytes;
    private int _maxRetryAttempts = 1;
    private TimeSpan _retryDelay = TimeSpan.FromMilliseconds(250);
    private TimeSpan _timeout = TimeSpan.FromSeconds(10);
    private Uri? _proxyEndpoint;
    private GitHubSecretLiveValidatorTlsMode _tlsMode = GitHubSecretLiveValidatorTlsMode.System;
    private Uri _userEndpoint = new("https://api.github.com/user");

    /// <summary>
    /// Creates default GitHub live validator options.
    /// </summary>
    /// <returns>Default GitHub live validator options.</returns>
    public static GitHubSecretLiveValidatorOptions CreateDefault()
    {
        return new GitHubSecretLiveValidatorOptions();
    }

    /// <summary>
    /// Gets or sets the GitHub REST API user endpoint used to validate a token.
    /// </summary>
    public Uri UserEndpoint
    {
        get => _userEndpoint;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            if (!value.IsAbsoluteUri)
            {
                throw new ArgumentException("Endpoint URI must be absolute.", nameof(value));
            }

            if (!string.IsNullOrEmpty(value.Query) || !string.IsNullOrEmpty(value.Fragment))
            {
                throw new ArgumentException("Endpoint URI must not include a query string or fragment.", nameof(value));
            }

            _userEndpoint = value;
        }
    }

    /// <summary>
    /// Gets or sets the HTTP user agent sent to GitHub.
    /// </summary>
    public string UserAgent { get; set; } = "picket/0.1";

    /// <summary>
    /// Gets or sets the GitHub REST API version header.
    /// </summary>
    public string ApiVersion { get; set; } = "2022-11-28";

    /// <summary>
    /// Gets or sets the endpoint guard options applied to the actual connected address.
    /// </summary>
    public EndpointGuardOptions EndpointGuardOptions
    {
        get => _endpointGuardOptions;
        set => _endpointGuardOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the per-request timeout.
    /// </summary>
    public TimeSpan Timeout
    {
        get => _timeout;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            _timeout = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum response bytes drained from GitHub responses.
    /// </summary>
    public int MaxResponseBytes
    {
        get => _maxResponseBytes;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxResponseBytes = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum retry attempts after the first request for transient provider failures.
    /// </summary>
    public int MaxRetryAttempts
    {
        get => _maxRetryAttempts;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0);
            _maxRetryAttempts = value;
        }
    }

    /// <summary>
    /// Gets or sets the delay between retry attempts for transient provider failures.
    /// </summary>
    public TimeSpan RetryDelay
    {
        get => _retryDelay;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _retryDelay = value;
        }
    }

    /// <summary>
    /// Gets or sets the optional HTTP proxy endpoint used for GitHub API requests.
    /// </summary>
    public Uri? ProxyEndpoint
    {
        get => _proxyEndpoint;
        set
        {
            if (value is null)
            {
                _proxyEndpoint = null;
                return;
            }

            if (!value.IsAbsoluteUri)
            {
                throw new ArgumentException("Proxy URI must be absolute.", nameof(value));
            }

            if (!value.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Proxy URI must use HTTPS.", nameof(value));
            }

            if (!string.IsNullOrEmpty(value.UserInfo)
                || !string.IsNullOrEmpty(value.Query)
                || !string.IsNullOrEmpty(value.Fragment))
            {
                throw new ArgumentException("Proxy URI must not include user info, a query string, or a fragment.", nameof(value));
            }

            _proxyEndpoint = value;
        }
    }

    /// <summary>
    /// Gets or sets the TLS protocol mode used for GitHub API requests.
    /// </summary>
    public GitHubSecretLiveValidatorTlsMode TlsMode
    {
        get => _tlsMode;
        set
        {
            if (value is not GitHubSecretLiveValidatorTlsMode.System
                and not GitHubSecretLiveValidatorTlsMode.Tls12OrLater)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            _tlsMode = value;
        }
    }

    /// <summary>
    /// Sets a custom message handler factory for tests and controlled hosts.
    /// </summary>
    /// <param name="messageHandlerFactory">The message handler factory.</param>
    public void SetMessageHandlerFactory(Func<HttpMessageHandler> messageHandlerFactory)
    {
        _messageHandlerFactory = messageHandlerFactory ?? throw new ArgumentNullException(nameof(messageHandlerFactory));
    }

    /// <summary>
    /// Sets a custom address resolver for tests and controlled hosts.
    /// </summary>
    /// <param name="addressResolver">The address resolver.</param>
    public void SetAddressResolver(Func<string, CancellationToken, ValueTask<IPAddress[]>> addressResolver)
    {
        _addressResolver = addressResolver ?? throw new ArgumentNullException(nameof(addressResolver));
    }

    internal HttpClient CreateHttpClient()
    {
        HttpMessageHandler handler = _messageHandlerFactory is null
            ? CreateHttpClientHandler()
            : _messageHandlerFactory();
        return new HttpClient(
            handler,
            disposeHandler: true)
        {
            Timeout = Timeout,
        };
    }

    private SocketsHttpHandler CreateHttpClientHandler()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = ConnectWithEndpointGuardAsync,
        };
        handler.SslOptions.EnabledSslProtocols = GetSslProtocols(_tlsMode);
        if (_proxyEndpoint is not null)
        {
            handler.Proxy = new WebProxy(_proxyEndpoint);
            handler.UseProxy = true;
        }

        return handler;
    }

    private async ValueTask<Stream> ConnectWithEndpointGuardAsync(
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

        EndpointGuardResult guardResult = EndpointGuard.Evaluate(CreateConnectedEndpoint(context), addresses, _endpointGuardOptions);
        if (!guardResult.IsAllowed)
        {
            throw new HttpRequestException(string.Concat("endpoint blocked: ", guardResult.BlockReason.ToString()));
        }

        return await ConnectToAllowedAddressAsync(context.DnsEndPoint, addresses, cancellationToken).ConfigureAwait(false);
    }

    private ValueTask<IPAddress[]> ResolveAddressesAsync(string host, CancellationToken cancellationToken)
    {
        return _addressResolver is null
            ? new ValueTask<IPAddress[]>(Dns.GetHostAddressesAsync(host, cancellationToken))
            : _addressResolver(host, cancellationToken);
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

    private static SslProtocols GetSslProtocols(GitHubSecretLiveValidatorTlsMode tlsMode)
    {
        return tlsMode switch
        {
            GitHubSecretLiveValidatorTlsMode.System => SslProtocols.None,
            GitHubSecretLiveValidatorTlsMode.Tls12OrLater => SslProtocols.Tls12 | SslProtocols.Tls13,
            _ => throw new ArgumentOutOfRangeException(nameof(tlsMode)),
        };
    }
}
