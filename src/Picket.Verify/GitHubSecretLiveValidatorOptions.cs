using System.Net;
using System.Security.Authentication;

namespace Picket.Verify;

/// <summary>
/// Configures GitHub live secret verification.
/// </summary>
public sealed class GitHubSecretLiveValidatorOptions
{
    private const int DefaultMaxResponseBytes = 65_536;

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

            if (!value.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !value.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Proxy URI must use HTTP or HTTPS.", nameof(value));
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

    private HttpClientHandler CreateHttpClientHandler()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            SslProtocols = GetSslProtocols(_tlsMode),
        };
        if (_proxyEndpoint is not null)
        {
            handler.Proxy = new WebProxy(_proxyEndpoint);
            handler.UseProxy = true;
        }

        return handler;
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
