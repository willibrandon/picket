using Picket.Security;
using System.Net;
using System.Security.Authentication;

namespace Picket.Verify;

/// <summary>
/// Configures explicit GitHub credential revocation requests.
/// </summary>
public sealed class GitHubCredentialRevokerOptions
{
    private EndpointGuardOptions _endpointGuardOptions = EndpointGuardOptions.CreateDefault();
    private Func<string, CancellationToken, ValueTask<IPAddress[]>>? _addressResolver;
    private Uri _credentialEndpoint = new("https://api.github.com/credentials/revoke");
    private Func<HttpMessageHandler>? _messageHandlerFactory;
    private Uri? _proxyEndpoint;
    private TimeSpan _timeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Creates default GitHub credential revoker options.
    /// </summary>
    /// <returns>Default GitHub credential revoker options.</returns>
    public static GitHubCredentialRevokerOptions CreateDefault()
    {
        return new GitHubCredentialRevokerOptions();
    }

    /// <summary>
    /// Gets or sets the GitHub REST API credential revocation endpoint.
    /// </summary>
    public Uri CredentialEndpoint
    {
        get => _credentialEndpoint;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            if (!value.IsAbsoluteUri)
            {
                throw new ArgumentException("Endpoint URI must be absolute.", nameof(value));
            }

            if (!string.IsNullOrEmpty(value.UserInfo)
                || !string.IsNullOrEmpty(value.Query)
                || !string.IsNullOrEmpty(value.Fragment))
            {
                throw new ArgumentException("Endpoint URI must not include user info, a query string, or a fragment.", nameof(value));
            }

            _credentialEndpoint = value;
        }
    }

    /// <summary>
    /// Gets or sets the HTTP user agent sent to GitHub.
    /// </summary>
    public string UserAgent { get; set; } = "picket/0.1";

    /// <summary>
    /// Gets or sets the GitHub REST API version header.
    /// </summary>
    public string ApiVersion { get; set; } = "2026-03-10";

    /// <summary>
    /// Gets or sets the endpoint guard policy applied before sending and at socket connect time.
    /// </summary>
    public EndpointGuardOptions EndpointGuardOptions
    {
        get => _endpointGuardOptions;
        set => _endpointGuardOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the request timeout.
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
    /// Gets or sets the optional HTTPS proxy endpoint used for GitHub API requests.
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
    /// Sets a custom message handler factory for tests and controlled hosts.
    /// </summary>
    /// <remarks>
    /// A custom handler replaces the default guarded transport. The revoker still performs its preflight
    /// endpoint check, but callers are responsible for equivalent connect-time enforcement.
    /// </remarks>
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
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout,
        };
    }

    private SocketsHttpHandler CreateHttpClientHandler()
    {
        return EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
        {
            AddressResolver = _addressResolver,
            EnabledSslProtocols = SslProtocols.None,
            EndpointGuardOptions = _endpointGuardOptions,
            Proxy = _proxyEndpoint is null ? null : new WebProxy(_proxyEndpoint),
        });
    }
}
