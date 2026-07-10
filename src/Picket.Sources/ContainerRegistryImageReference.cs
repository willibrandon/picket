namespace Picket.Sources;

/// <summary>
/// Represents a normalized OCI or Docker container image reference.
/// </summary>
public sealed class ContainerRegistryImageReference
{
    private const string DefaultRegistryHost = "docker.io";
    private const string DockerHubRegistryHost = "registry-1.docker.io";

    private ContainerRegistryImageReference(
        string registryHost,
        string repository,
        string reference,
        bool isDigest,
        Uri defaultEndpoint)
    {
        RegistryHost = registryHost;
        Repository = repository;
        Reference = reference;
        IsDigest = isDigest;
        DefaultEndpoint = defaultEndpoint;
    }

    /// <summary>
    /// Gets the registry host represented by the image name.
    /// </summary>
    public string RegistryHost { get; }

    /// <summary>
    /// Gets the normalized repository name.
    /// </summary>
    public string Repository { get; }

    /// <summary>
    /// Gets the tag or digest reference.
    /// </summary>
    public string Reference { get; }

    /// <summary>
    /// Gets a value indicating whether <see cref="Reference" /> is a digest.
    /// </summary>
    public bool IsDigest { get; }

    /// <summary>
    /// Gets the default registry API endpoint derived from the image name.
    /// </summary>
    public Uri DefaultEndpoint { get; }

    /// <summary>
    /// Gets the canonical normalized image name.
    /// </summary>
    public string CanonicalName => IsDigest
        ? string.Concat(RegistryHost, "/", Repository, "@", Reference)
        : string.Concat(RegistryHost, "/", Repository, ":", Reference);

    /// <summary>
    /// Parses an OCI or Docker image reference.
    /// </summary>
    /// <param name="value">The image reference to parse.</param>
    /// <returns>The normalized image reference.</returns>
    public static ContainerRegistryImageReference Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string normalized = value.Trim();
        if (normalized.Contains("://", StringComparison.Ordinal))
        {
            throw new ArgumentException("Container image references do not include a URI scheme; use a registry endpoint override for custom schemes or paths.", nameof(value));
        }

        SplitReference(normalized, out string name, out string reference, out bool isDigest);
        SplitRegistry(name, out string registryHost, out string repository);
        ValidateRepository(repository, nameof(value));
        if (isDigest)
        {
            ValidateDigest(reference, nameof(value));
        }
        else
        {
            ValidateTag(reference, nameof(value));
        }

        string endpointHost = registryHost.Equals(DefaultRegistryHost, StringComparison.OrdinalIgnoreCase)
            ? DockerHubRegistryHost
            : registryHost;
        if (!Uri.TryCreate(string.Concat("https://", endpointHost, "/"), UriKind.Absolute, out Uri? endpoint))
        {
            throw new ArgumentException("Container image registry host is invalid.", nameof(value));
        }

        return new ContainerRegistryImageReference(
            registryHost.ToLowerInvariant(),
            repository.ToLowerInvariant(),
            isDigest ? reference.ToLowerInvariant() : reference,
            isDigest,
            endpoint);
    }

    internal static bool TryParseSha256Digest(string value, out byte[] digestBytes)
    {
        digestBytes = [];
        if (value.Length != 71 || !value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            digestBytes = Convert.FromHexString(value.AsSpan(7));
            return digestBytes.Length == 32;
        }
        catch (FormatException)
        {
            digestBytes = [];
            return false;
        }
    }

    private static void SplitReference(
        string value,
        out string name,
        out string reference,
        out bool isDigest)
    {
        int digestSeparator = value.IndexOf('@', StringComparison.Ordinal);
        if (digestSeparator >= 0)
        {
            if (digestSeparator == 0
                || digestSeparator == value.Length - 1
                || value.IndexOf('@', digestSeparator + 1) >= 0)
            {
                throw new ArgumentException("Container image digest references must use name@sha256:<digest>.", nameof(value));
            }

            name = value[..digestSeparator];
            reference = value[(digestSeparator + 1)..];
            isDigest = true;
            return;
        }

        int lastSlash = value.LastIndexOf('/');
        int tagSeparator = value.LastIndexOf(':');
        if (tagSeparator > lastSlash)
        {
            if (tagSeparator == value.Length - 1)
            {
                throw new ArgumentException("Container image tags must not be empty.", nameof(value));
            }

            name = value[..tagSeparator];
            reference = value[(tagSeparator + 1)..];
        }
        else
        {
            name = value;
            reference = "latest";
        }

        isDigest = false;
    }

    private static void SplitRegistry(string value, out string registryHost, out string repository)
    {
        int separator = value.IndexOf('/');
        string firstSegment = separator < 0 ? value : value[..separator];
        bool hasExplicitRegistry = firstSegment.Contains('.')
            || firstSegment.Contains(':')
            || firstSegment.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        if (hasExplicitRegistry)
        {
            if (separator < 0 || separator == value.Length - 1)
            {
                throw new ArgumentException("Container image references with an explicit registry must include a repository.", nameof(value));
            }

            registryHost = firstSegment;
            repository = value[(separator + 1)..];
            return;
        }

        registryHost = DefaultRegistryHost;
        repository = separator < 0 ? string.Concat("library/", value) : value;
    }

    private static void ValidateRepository(string value, string parameterName)
    {
        if (value.Length == 0 || value.Length >= 256 || value.StartsWith('/') || value.EndsWith('/'))
        {
            throw new ArgumentException("Container image repository names must contain 1 through 255 characters.", parameterName);
        }

        ReadOnlySpan<char> remaining = value;
        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOf('/');
            ReadOnlySpan<char> segment = separator < 0 ? remaining : remaining[..separator];
            if (!IsRepositorySegment(segment))
            {
                throw new ArgumentException("Container image repository segments must use lowercase ASCII letters, digits, periods, underscores, or hyphens.", parameterName);
            }

            if (separator < 0)
            {
                break;
            }

            remaining = remaining[(separator + 1)..];
        }
    }

    private static bool IsRepositorySegment(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || !IsLowerAlphaNumeric(value[0]) || !IsLowerAlphaNumeric(value[^1]))
        {
            return false;
        }

        for (int i = 1; i < value.Length - 1; i++)
        {
            char character = value[i];
            if (!IsLowerAlphaNumeric(character) && character is not '.' and not '_' and not '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsLowerAlphaNumeric(char value)
    {
        return value is >= 'a' and <= 'z' or >= '0' and <= '9';
    }

    private static void ValidateTag(string value, string parameterName)
    {
        if (value.Length is 0 or > 128 || !IsTagStart(value[0]))
        {
            throw new ArgumentException("Container image tags must contain 1 through 128 valid tag characters.", parameterName);
        }

        for (int i = 1; i < value.Length; i++)
        {
            char character = value[i];
            if (!IsTagStart(character) && character is not '.' and not '-')
            {
                throw new ArgumentException("Container image tag contains an unsupported character.", parameterName);
            }
        }
    }

    private static bool IsTagStart(char value)
    {
        return value is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z'
            or >= '0' and <= '9'
            or '_';
    }

    private static void ValidateDigest(string value, string parameterName)
    {
        if (!TryParseSha256Digest(value, out _))
        {
            throw new ArgumentException("Container image digests must use sha256 followed by 64 hexadecimal characters.", parameterName);
        }
    }
}
