namespace Picket.Verify;

/// <summary>
/// Configures GitHub live secret verification.
/// </summary>
public sealed class GitHubSecretLiveValidatorOptions
{
    private const int DefaultMaxResponseBytes = 65_536;

    private Func<HttpMessageHandler>? _messageHandlerFactory;
    private int _maxResponseBytes = DefaultMaxResponseBytes;
    private TimeSpan _timeout = TimeSpan.FromSeconds(10);
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
    /// Sets a custom message handler factory for tests and controlled hosts.
    /// </summary>
    /// <param name="messageHandlerFactory">The message handler factory.</param>
    public void SetMessageHandlerFactory(Func<HttpMessageHandler> messageHandlerFactory)
    {
        _messageHandlerFactory = messageHandlerFactory ?? throw new ArgumentNullException(nameof(messageHandlerFactory));
    }

    internal HttpClient CreateHttpClient()
    {
        HttpClient client = _messageHandlerFactory is null
            ? new HttpClient()
            : new HttpClient(_messageHandlerFactory(), disposeHandler: true);
        client.Timeout = Timeout;
        return client;
    }
}
