using System.Diagnostics.CodeAnalysis;
using System.Globalization;

/// <summary>
/// Validates and forwards the source selected by the Picket GitHub Action.
/// </summary>
internal sealed class PicketActionScanSource
{
    /// <summary>
    /// Picket's Docker archive source option.
    /// </summary>
    private const string DockerArchiveOption = "--docker-archive";

    /// <summary>
    /// Picket's OCI archive source option.
    /// </summary>
    private const string OciArchiveOption = "--oci-archive";

    /// <summary>
    /// Picket's registry image source option.
    /// </summary>
    private const string RegistryImageOption = "--registry-image";

    private readonly bool _allowInsecureSourceEndpoints;
    private readonly bool _allowNonPublicSourceEndpoints;
    private readonly string _registryAuthenticationEndpoint;
    private readonly string _registryEndpoint;
    private readonly string _registryMaxImageMegabytes;
    private readonly string _registryPasswordEnvironmentVariable;
    private readonly string _registryPlatform;
    private readonly string _registryTokenEnvironmentVariable;
    private readonly string _registryUsernameEnvironmentVariable;
    private readonly string _sourceOption;
    private readonly string _sourceValue;

    private PicketActionScanSource(
        string sourceOption,
        string sourceValue,
        string registryEndpoint,
        string registryAuthenticationEndpoint,
        string registryTokenEnvironmentVariable,
        string registryUsernameEnvironmentVariable,
        string registryPasswordEnvironmentVariable,
        string registryPlatform,
        string registryMaxImageMegabytes,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints)
    {
        _sourceOption = sourceOption;
        _sourceValue = sourceValue;
        _registryEndpoint = registryEndpoint;
        _registryAuthenticationEndpoint = registryAuthenticationEndpoint;
        _registryTokenEnvironmentVariable = registryTokenEnvironmentVariable;
        _registryUsernameEnvironmentVariable = registryUsernameEnvironmentVariable;
        _registryPasswordEnvironmentVariable = registryPasswordEnvironmentVariable;
        _registryPlatform = registryPlatform;
        _registryMaxImageMegabytes = registryMaxImageMegabytes;
        _allowNonPublicSourceEndpoints = allowNonPublicSourceEndpoints;
        _allowInsecureSourceEndpoints = allowInsecureSourceEndpoints;
    }

    /// <summary>
    /// Validates the Action source inputs and creates the selected source.
    /// </summary>
    /// <param name="path">The optional filesystem path.</param>
    /// <param name="dockerArchive">The optional Docker archive path.</param>
    /// <param name="ociArchive">The optional OCI archive path.</param>
    /// <param name="registryImage">The optional registry image reference.</param>
    /// <param name="source">The validated source when successful.</param>
    /// <param name="error">The validation error when unsuccessful.</param>
    /// <param name="registryEndpoint">The optional registry API endpoint.</param>
    /// <param name="registryAuthenticationEndpoint">The optional registry authentication endpoint.</param>
    /// <param name="registryTokenEnvironmentVariable">The optional bearer-token environment variable name.</param>
    /// <param name="registryUsernameEnvironmentVariable">The optional username environment variable name.</param>
    /// <param name="registryPasswordEnvironmentVariable">The optional password environment variable name.</param>
    /// <param name="registryPlatform">The optional image platform selector.</param>
    /// <param name="registryMaxImageMegabytes">The optional aggregate image download cap.</param>
    /// <param name="allowNonPublicSourceEndpoints">Whether non-public registry endpoints are allowed.</param>
    /// <param name="allowInsecureSourceEndpoints">Whether insecure registry endpoints are allowed.</param>
    /// <returns><see langword="true"/> when the source inputs are valid; otherwise <see langword="false"/>.</returns>
    internal static bool TryCreate(
        string path,
        string dockerArchive,
        string ociArchive,
        string registryImage,
        [NotNullWhen(true)] out PicketActionScanSource? source,
        out string error,
        string registryEndpoint = "",
        string registryAuthenticationEndpoint = "",
        string registryTokenEnvironmentVariable = "",
        string registryUsernameEnvironmentVariable = "",
        string registryPasswordEnvironmentVariable = "",
        string registryPlatform = "",
        string registryMaxImageMegabytes = "",
        bool allowNonPublicSourceEndpoints = false,
        bool allowInsecureSourceEndpoints = false)
    {
        int primarySourceCount = CountValue(path)
            + CountValue(dockerArchive)
            + CountValue(ociArchive)
            + CountValue(registryImage);
        if (primarySourceCount > 1)
        {
            source = null;
            error = "path, docker-archive, oci-archive, and registry-image are mutually exclusive; specify exactly one source.";
            return false;
        }

        bool registryImageSpecified = !string.IsNullOrWhiteSpace(registryImage);
        bool registryOptionSpecified = !string.IsNullOrWhiteSpace(registryEndpoint)
            || !string.IsNullOrWhiteSpace(registryAuthenticationEndpoint)
            || !string.IsNullOrWhiteSpace(registryTokenEnvironmentVariable)
            || !string.IsNullOrWhiteSpace(registryUsernameEnvironmentVariable)
            || !string.IsNullOrWhiteSpace(registryPasswordEnvironmentVariable)
            || !string.IsNullOrWhiteSpace(registryPlatform)
            || !string.IsNullOrWhiteSpace(registryMaxImageMegabytes)
            || allowNonPublicSourceEndpoints
            || allowInsecureSourceEndpoints;
        if (registryOptionSpecified && !registryImageSpecified)
        {
            source = null;
            error = "registry source options require registry-image.";
            return false;
        }

        bool tokenSpecified = !string.IsNullOrWhiteSpace(registryTokenEnvironmentVariable);
        bool usernameSpecified = !string.IsNullOrWhiteSpace(registryUsernameEnvironmentVariable);
        bool passwordSpecified = !string.IsNullOrWhiteSpace(registryPasswordEnvironmentVariable);
        if ((tokenSpecified && (usernameSpecified || passwordSpecified)) || usernameSpecified != passwordSpecified)
        {
            source = null;
            error = "registry authentication accepts either registry-token-env or both registry-username-env and registry-password-env.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(registryMaxImageMegabytes)
            && (!long.TryParse(registryMaxImageMegabytes, NumberStyles.None, CultureInfo.InvariantCulture, out long maxImageMegabytes)
                || maxImageMegabytes <= 0))
        {
            source = null;
            error = "registry-max-image-megabytes must be a positive integer.";
            return false;
        }

        string sourceOption;
        string sourceValue;
        if (!string.IsNullOrWhiteSpace(dockerArchive))
        {
            sourceOption = DockerArchiveOption;
            sourceValue = dockerArchive;
        }
        else if (!string.IsNullOrWhiteSpace(ociArchive))
        {
            sourceOption = OciArchiveOption;
            sourceValue = ociArchive;
        }
        else if (registryImageSpecified)
        {
            sourceOption = RegistryImageOption;
            sourceValue = registryImage;
        }
        else
        {
            sourceOption = string.Empty;
            sourceValue = string.IsNullOrWhiteSpace(path) ? "." : path;
        }

        source = new PicketActionScanSource(
            sourceOption,
            sourceValue,
            registryEndpoint,
            registryAuthenticationEndpoint,
            registryTokenEnvironmentVariable,
            registryUsernameEnvironmentVariable,
            registryPasswordEnvironmentVariable,
            registryPlatform,
            registryMaxImageMegabytes,
            allowNonPublicSourceEndpoints,
            allowInsecureSourceEndpoints);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Appends the selected source to a Picket CLI argument list.
    /// </summary>
    /// <param name="arguments">The destination argument list.</param>
    /// <param name="resolveWorkspacePath">Resolves local paths against the GitHub workspace.</param>
    internal void AppendArguments(List<string> arguments, Func<string, string> resolveWorkspacePath)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(resolveWorkspacePath);

        if (_sourceOption.Length == 0)
        {
            arguments.Add(resolveWorkspacePath(_sourceValue));
            return;
        }

        arguments.Add(_sourceOption);
        arguments.Add(_sourceOption == RegistryImageOption ? _sourceValue : resolveWorkspacePath(_sourceValue));
        if (_sourceOption != RegistryImageOption)
        {
            return;
        }

        AddOptionalValue(arguments, "--registry-endpoint", _registryEndpoint);
        AddOptionalValue(arguments, "--registry-auth-endpoint", _registryAuthenticationEndpoint);
        AddOptionalValue(arguments, "--registry-token-env", _registryTokenEnvironmentVariable);
        AddOptionalValue(arguments, "--registry-username-env", _registryUsernameEnvironmentVariable);
        AddOptionalValue(arguments, "--registry-password-env", _registryPasswordEnvironmentVariable);
        AddOptionalValue(arguments, "--registry-platform", _registryPlatform);
        AddOptionalValue(arguments, "--registry-max-image-megabytes", _registryMaxImageMegabytes);
        if (_allowNonPublicSourceEndpoints)
        {
            arguments.Add("--allow-non-public-source-endpoints");
        }

        if (_allowInsecureSourceEndpoints)
        {
            arguments.Add("--allow-insecure-source-endpoints");
        }
    }

    /// <summary>
    /// Appends an option and non-empty value.
    /// </summary>
    /// <param name="arguments">The destination argument list.</param>
    /// <param name="option">The option name.</param>
    /// <param name="value">The optional value.</param>
    private static void AddOptionalValue(List<string> arguments, string option, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            arguments.Add(option);
            arguments.Add(value);
        }
    }

    /// <summary>
    /// Returns one for a non-empty input and zero otherwise.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <returns>One when the input is specified; otherwise zero.</returns>
    private static int CountValue(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? 0 : 1;
    }
}
