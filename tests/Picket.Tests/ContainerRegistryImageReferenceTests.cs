using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests OCI and Docker image reference parsing.
/// </summary>
[TestClass]
public sealed class ContainerRegistryImageReferenceTests
{
    private static readonly string[] s_invalidReferences =
    [
        "https://registry.example/team/app:latest",
        "registry.example",
        "registry.example/Team/app:latest",
        "registry.example/team/../app:latest",
        "registry.example/team/app:",
        "registry.example/team/app@sha256:abc",
    ];

    /// <summary>
    /// Verifies Docker Hub shorthand resolves to the official v2 registry endpoint and library namespace.
    /// </summary>
    [TestMethod]
    public void ParseNormalizesDockerHubShorthand()
    {
        ContainerRegistryImageReference image = ContainerRegistryImageReference.Parse("ubuntu");

        Assert.AreEqual("docker.io", image.RegistryHost);
        Assert.AreEqual("library/ubuntu", image.Repository);
        Assert.AreEqual("latest", image.Reference);
        Assert.IsFalse(image.IsDigest);
        Assert.AreEqual("docker.io/library/ubuntu:latest", image.CanonicalName);
        Assert.AreEqual("https://registry-1.docker.io/", image.DefaultEndpoint.AbsoluteUri);
    }

    /// <summary>
    /// Verifies explicit registries, ports, tags, and digests retain their intended components.
    /// </summary>
    [TestMethod]
    public void ParsePreservesExplicitRegistryReferences()
    {
        ContainerRegistryImageReference tagged = ContainerRegistryImageReference.Parse("registry.example:5443/team/app:release-1");
        string digestValue = string.Concat("sha256:", new string('a', 64));
        ContainerRegistryImageReference digested = ContainerRegistryImageReference.Parse($"ghcr.io/willibrandon/picket@{digestValue}");

        Assert.AreEqual("registry.example:5443", tagged.RegistryHost);
        Assert.AreEqual("team/app", tagged.Repository);
        Assert.AreEqual("release-1", tagged.Reference);
        Assert.AreEqual("https://registry.example:5443/", tagged.DefaultEndpoint.AbsoluteUri);
        Assert.AreEqual($"ghcr.io/willibrandon/picket@{digestValue}", digested.CanonicalName);
        Assert.AreEqual(digestValue, digested.Reference);
        Assert.IsTrue(digested.IsDigest);
    }

    /// <summary>
    /// Verifies invalid or ambiguous image references fail closed.
    /// </summary>
    [TestMethod]
    public void ParseRejectsInvalidReferences()
    {
        for (int i = 0; i < s_invalidReferences.Length; i++)
        {
            Assert.ThrowsExactly<ArgumentException>(() => ContainerRegistryImageReference.Parse(s_invalidReferences[i]));
        }
    }

    /// <summary>
    /// Verifies platform filters normalize common architecture aliases without changing OCI semantics.
    /// </summary>
    [TestMethod]
    public void SourceOptionsNormalizesPlatformAliases()
    {
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("ubuntu"),
            platform: "Linux/X64");

        Assert.AreEqual("linux/amd64", options.Platform);
    }

    /// <summary>
    /// Verifies registry credentials retain leading and trailing whitespace from their environment variables.
    /// </summary>
    [TestMethod]
    public void SourceOptionsPreservesCredentialValuesExactly()
    {
        const string Credential = "  registry password  ";
        const string Username = " registry user ";
        var options = new ContainerRegistrySourceOptions(
            ContainerRegistryImageReference.Parse("registry.example/team/app"),
            credentialKind: ContainerRegistryCredentialKind.Basic,
            credential: Credential,
            username: Username);

        Assert.AreEqual(Credential, options.Credential);
        Assert.AreEqual(Username, options.Username);
    }

    /// <summary>
    /// Verifies pre-issued bearer credentials must be valid for an Authorization header.
    /// </summary>
    [TestMethod]
    public void SourceOptionsValidateBearerTokenGrammar()
    {
        ContainerRegistryImageReference image = ContainerRegistryImageReference.Parse("ubuntu");
        var valid = new ContainerRegistrySourceOptions(
            image,
            credentialKind: ContainerRegistryCredentialKind.BearerToken,
            credential: "abc.DEF_123-~+/==");

        Assert.AreEqual("abc.DEF_123-~+/==", valid.Credential);
        Assert.ThrowsExactly<ArgumentException>(() => new ContainerRegistrySourceOptions(
            image,
            credentialKind: ContainerRegistryCredentialKind.BearerToken,
            credential: "abc def"));
        Assert.ThrowsExactly<ArgumentException>(() => new ContainerRegistrySourceOptions(
            image,
            credentialKind: ContainerRegistryCredentialKind.BearerToken,
            credential: "=abc"));
    }

    /// <summary>
    /// Verifies remote registry byte limits cannot be disabled.
    /// </summary>
    [TestMethod]
    public void SourceOptionsRejectsUnboundedRemoteDownloads()
    {
        ContainerRegistryImageReference image = ContainerRegistryImageReference.Parse("ubuntu");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxBlobBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxImageBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxTargetBytes: 0));
    }

    /// <summary>
    /// Verifies remote layer traversal cannot disable archive safety limits without disabling traversal itself.
    /// </summary>
    [TestMethod]
    public void SourceOptionsRequireArchiveLimitsWhileTraversalIsEnabled()
    {
        ContainerRegistryImageReference image = ContainerRegistryImageReference.Parse("ubuntu");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxArchiveEntries: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxArchiveBytes: 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxArchiveBytes: null));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ContainerRegistrySourceOptions(image, maxArchiveCompressionRatio: 0));

        var metadataOnlyOptions = new ContainerRegistrySourceOptions(
            image,
            maxArchiveDepth: 0,
            maxArchiveEntries: 0,
            maxArchiveBytes: null,
            maxArchiveCompressionRatio: 0);
        Assert.AreEqual(0, metadataOnlyOptions.MaxArchiveDepth);
        Assert.AreEqual(0, metadataOnlyOptions.MaxArchiveEntries);
        Assert.IsNull(metadataOnlyOptions.MaxArchiveBytes);
        Assert.AreEqual(0, metadataOnlyOptions.MaxArchiveCompressionRatio);
    }
}
