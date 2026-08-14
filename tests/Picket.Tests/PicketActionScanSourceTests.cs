namespace Picket.Tests;

/// <summary>
/// Tests GitHub Action scan-source validation and CLI argument forwarding.
/// </summary>
[TestClass]
public sealed class PicketActionScanSourceTests
{
    private static readonly string[] s_defaultWorkspaceArguments = ["workspace:."];
    private static readonly string[] s_explicitWorkspaceArguments = ["workspace:src/repository"];
    private static readonly string[] s_registryArguments =
    [
        "--registry-image",
        "registry.example/team/app:1.2.3",
        "--registry-endpoint",
        "https://mirror.example/v2",
        "--registry-auth-endpoint",
        "https://auth.example/token",
        "--registry-username-env",
        "REGISTRY_USERNAME",
        "--registry-password-env",
        "REGISTRY_PASSWORD",
        "--registry-platform",
        "linux/arm64/v8",
        "--registry-max-image-megabytes",
        "768",
        "--allow-non-public-source-endpoints",
        "--allow-insecure-source-endpoints",
    ];
    private static readonly string[] s_registryTokenArguments =
    [
        "--registry-image",
        "ghcr.io/example/app@sha256:0123456789abcdef",
        "--registry-token-env",
        "REGISTRY_TOKEN",
    ];

    /// <summary>
    /// Verifies that an omitted source retains the Action's workspace default.
    /// </summary>
    [TestMethod]
    public void TryCreateNoExplicitSourceAppendsWorkspaceFallback()
    {
        bool created = PicketActionScanSource.TryCreate("", "", "", "", out PicketActionScanSource? source, out string error);

        Assert.IsTrue(created);
        Assert.AreEqual(string.Empty, error);
        Assert.IsNotNull(source);
        var arguments = new List<string>();
        source.AppendArguments(arguments, value => $"workspace:{value}");

        CollectionAssert.AreEqual(s_defaultWorkspaceArguments, arguments);
    }

    /// <summary>
    /// Verifies that an explicit filesystem path remains a positional source.
    /// </summary>
    [TestMethod]
    public void TryCreateExplicitPathAppendsResolvedPositionalSource()
    {
        bool created = PicketActionScanSource.TryCreate("src/repository", "", "", "", out PicketActionScanSource? source, out string error);

        Assert.IsTrue(created);
        Assert.AreEqual(string.Empty, error);
        Assert.IsNotNull(source);
        var arguments = new List<string>();
        source.AppendArguments(arguments, value => $"workspace:{value}");

        CollectionAssert.AreEqual(s_explicitWorkspaceArguments, arguments);
    }

    /// <summary>
    /// Verifies that Docker and OCI archive paths are resolved relative to the workspace.
    /// </summary>
    /// <param name="dockerArchive">The Docker archive input.</param>
    /// <param name="ociArchive">The OCI archive input.</param>
    /// <param name="expectedOption">The expected CLI option.</param>
    /// <param name="expectedPath">The expected input path.</param>
    [TestMethod]
    [DataRow("artifacts/image.tar", "", "--docker-archive", "artifacts/image.tar", DisplayName = "Docker archive")]
    [DataRow("", "artifacts/image-oci.tar", "--oci-archive", "artifacts/image-oci.tar", DisplayName = "OCI archive")]
    public void TryCreateArchiveAppendsResolvedOption(
        string dockerArchive,
        string ociArchive,
        string expectedOption,
        string expectedPath)
    {
        bool created = PicketActionScanSource.TryCreate("", dockerArchive, ociArchive, "", out PicketActionScanSource? source, out string error);

        Assert.IsTrue(created);
        Assert.AreEqual(string.Empty, error);
        Assert.IsNotNull(source);
        var arguments = new List<string>();
        source.AppendArguments(arguments, value => $"workspace:{value}");

        CollectionAssert.AreEqual(new[] { expectedOption, $"workspace:{expectedPath}" }, arguments);
    }

    /// <summary>
    /// Verifies that registry image and Basic-auth environment names are forwarded exactly.
    /// </summary>
    [TestMethod]
    public void TryCreateRegistryImageAppendsAllRegistryOptionsWithoutPathResolution()
    {
        bool created = PicketActionScanSource.TryCreate(
            "",
            "",
            "",
            "registry.example/team/app:1.2.3",
            out PicketActionScanSource? source,
            out string error,
            "https://mirror.example/v2",
            "https://auth.example/token",
            registryUsernameEnvironmentVariable: "REGISTRY_USERNAME",
            registryPasswordEnvironmentVariable: "REGISTRY_PASSWORD",
            registryPlatform: "linux/arm64/v8",
            registryMaxImageMegabytes: "768",
            allowNonPublicSourceEndpoints: true,
            allowInsecureSourceEndpoints: true);

        Assert.IsTrue(created);
        Assert.AreEqual(string.Empty, error);
        Assert.IsNotNull(source);
        var arguments = new List<string>();
        source.AppendArguments(arguments, _ => throw new AssertFailedException("Registry references must not be path-resolved."));

        CollectionAssert.AreEqual(s_registryArguments, arguments);
    }

    /// <summary>
    /// Verifies bearer-token authentication can be selected independently.
    /// </summary>
    [TestMethod]
    public void TryCreateRegistryImageAppendsBearerTokenEnvironmentName()
    {
        bool created = PicketActionScanSource.TryCreate(
            "",
            "",
            "",
            "ghcr.io/example/app@sha256:0123456789abcdef",
            out PicketActionScanSource? source,
            out string error,
            registryTokenEnvironmentVariable: "REGISTRY_TOKEN");

        Assert.IsTrue(created);
        Assert.AreEqual(string.Empty, error);
        Assert.IsNotNull(source);
        var arguments = new List<string>();
        source.AppendArguments(arguments, Path.GetFullPath);

        CollectionAssert.AreEqual(s_registryTokenArguments, arguments);
    }

    /// <summary>
    /// Verifies that explicit primary source combinations are rejected.
    /// </summary>
    /// <param name="path">The path input.</param>
    /// <param name="dockerArchive">The Docker archive input.</param>
    /// <param name="ociArchive">The OCI archive input.</param>
    /// <param name="registryImage">The registry image input.</param>
    [TestMethod]
    [DataRow(".", "image.tar", "", "", DisplayName = "Path and Docker archive")]
    [DataRow("", "image.tar", "image-oci.tar", "", DisplayName = "Docker and OCI archives")]
    [DataRow(".", "", "", "example/app:latest", DisplayName = "Path and registry image")]
    public void TryCreateMultiplePrimarySourcesReturnsActionableError(
        string path,
        string dockerArchive,
        string ociArchive,
        string registryImage)
    {
        bool created = PicketActionScanSource.TryCreate(
            path,
            dockerArchive,
            ociArchive,
            registryImage,
            out PicketActionScanSource? source,
            out string error);

        Assert.IsFalse(created);
        Assert.IsNull(source);
        Assert.AreEqual(
            "path, docker-archive, oci-archive, and registry-image are mutually exclusive; specify exactly one source.",
            error);
    }

    /// <summary>
    /// Verifies that registry-only options cannot silently affect a workspace scan.
    /// </summary>
    [TestMethod]
    public void TryCreateRegistryOptionWithoutImageReturnsActionableError()
    {
        bool created = PicketActionScanSource.TryCreate(
            "",
            "",
            "",
            "",
            out PicketActionScanSource? source,
            out string error,
            registryPlatform: "linux/amd64");

        Assert.IsFalse(created);
        Assert.IsNull(source);
        Assert.AreEqual("registry source options require registry-image.", error);
    }

    /// <summary>
    /// Verifies that mixed or incomplete registry authentication is rejected.
    /// </summary>
    /// <param name="tokenEnvironmentVariable">The bearer-token environment variable name.</param>
    /// <param name="usernameEnvironmentVariable">The username environment variable name.</param>
    /// <param name="passwordEnvironmentVariable">The password environment variable name.</param>
    [TestMethod]
    [DataRow("TOKEN", "USERNAME", "PASSWORD", DisplayName = "Bearer and Basic")]
    [DataRow("", "USERNAME", "", DisplayName = "Missing password")]
    [DataRow("", "", "PASSWORD", DisplayName = "Missing username")]
    public void TryCreateInvalidRegistryAuthenticationReturnsActionableError(
        string tokenEnvironmentVariable,
        string usernameEnvironmentVariable,
        string passwordEnvironmentVariable)
    {
        bool created = PicketActionScanSource.TryCreate(
            "",
            "",
            "",
            "example/app:latest",
            out PicketActionScanSource? source,
            out string error,
            registryTokenEnvironmentVariable: tokenEnvironmentVariable,
            registryUsernameEnvironmentVariable: usernameEnvironmentVariable,
            registryPasswordEnvironmentVariable: passwordEnvironmentVariable);

        Assert.IsFalse(created);
        Assert.IsNull(source);
        Assert.AreEqual(
            "registry authentication accepts either registry-token-env or both registry-username-env and registry-password-env.",
            error);
    }

    /// <summary>
    /// Verifies that the registry image download cap is a strictly positive integer.
    /// </summary>
    /// <param name="value">The invalid input value.</param>
    [TestMethod]
    [DataRow("0")]
    [DataRow("-1")]
    [DataRow("1.5")]
    [DataRow("unbounded")]
    public void TryCreateInvalidRegistryImageLimitReturnsActionableError(string value)
    {
        bool created = PicketActionScanSource.TryCreate(
            "",
            "",
            "",
            "example/app:latest",
            out PicketActionScanSource? source,
            out string error,
            registryMaxImageMegabytes: value);

        Assert.IsFalse(created);
        Assert.IsNull(source);
        Assert.AreEqual("registry-max-image-megabytes must be a positive integer.", error);
    }
}
