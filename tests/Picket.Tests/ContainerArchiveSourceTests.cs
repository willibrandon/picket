using Picket.Sources;
using System.Text;
using ZstdSharp;

namespace Picket.Tests;

/// <summary>
/// Tests local Docker and OCI image archive source enumeration.
/// </summary>
[TestClass]
public sealed class ContainerArchiveSourceTests
{
    /// <summary>
    /// Verifies that Docker image archives enumerate layer tar files using container provenance.
    /// </summary>
    [TestMethod]
    public void EnumerateReadsDockerLayerTarEntries()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = Path.Combine(temp.Path, "image.tar");
        byte[] layerBytes = TarTestData.CreateTarBytes(("app/settings.txt", Encoding.UTF8.GetBytes("token-12345")));
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("manifest.json", Encoding.UTF8.GetBytes("""[{"Layers":["layer/layer.tar"]}]""")),
                ("layer/layer.tar", layerBytes)));

        List<SourceFile> files = ContainerArchiveSource.Enumerate(
            archivePath,
            "docker-archive",
            maxArchiveDepth: 1,
            maxArchiveEntries: 16,
            maxArchiveBytes: 1_000_000,
            maxArchiveCompressionRatio: 100,
            maxTargetBytes: null);
        SourceFile? layerFile = files.FirstOrDefault(static file => file.DisplayPath.Equals(
            "docker-archive/image.tar!layer/layer.tar!app/settings.txt",
            StringComparison.Ordinal));

        Assert.IsNotNull(layerFile);
        Assert.Contains("docker-archive/image.tar!manifest.json", files.Select(static file => file.DisplayPath).ToArray());
        Assert.AreEqual("token-12345", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies that OCI image archive gzip layer blobs enumerate with container provenance.
    /// </summary>
    [TestMethod]
    public void EnumerateReadsOciGzipLayerBlobs()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = Path.Combine(temp.Path, "image-oci.tar");
        byte[] layerTarBytes = TarTestData.CreateTarBytes(("etc/secret.conf", Encoding.UTF8.GetBytes("token-67890")));
        byte[] layerGzipBytes = TarTestData.CreateGzipBytes(layerTarBytes);
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("oci-layout", Encoding.UTF8.GetBytes("""{"imageLayoutVersion":"1.0.0"}""")),
                ("index.json", Encoding.UTF8.GetBytes("""{"manifests":[]}""")),
                ("blobs/sha256/layer", layerGzipBytes)));

        List<SourceFile> files = ContainerArchiveSource.Enumerate(
            archivePath,
            "oci-archive",
            maxArchiveDepth: 1,
            maxArchiveEntries: 16,
            maxArchiveBytes: 1_000_000,
            maxArchiveCompressionRatio: 100,
            maxTargetBytes: null);
        SourceFile? layerFile = files.FirstOrDefault(static file => file.DisplayPath.Equals(
            "oci-archive/image-oci.tar!blobs/sha256/layer!etc/secret.conf",
            StringComparison.Ordinal));

        Assert.IsNotNull(layerFile);
        Assert.AreEqual("token-67890", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies that OCI image archive zstd layer blobs enumerate through the shared bounded archive reader.
    /// </summary>
    [TestMethod]
    public void EnumerateReadsOciZstandardLayerBlobs()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = Path.Combine(temp.Path, "image-zstd.tar");
        byte[] layerTarBytes = TarTestData.CreateTarBytes(("etc/zstd-secret.conf", Encoding.UTF8.GetBytes("token-zstd-12345")));
        byte[] layerZstandardBytes = CreateZstandardBytes(layerTarBytes);
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(
                ("oci-layout", Encoding.UTF8.GetBytes("""{"imageLayoutVersion":"1.0.0"}""")),
                ("index.json", Encoding.UTF8.GetBytes("""{"manifests":[]}""")),
                ("blobs/sha256/layer", layerZstandardBytes)));

        List<SourceFile> files = ContainerArchiveSource.Enumerate(
            archivePath,
            "oci-archive",
            maxArchiveDepth: 1,
            maxArchiveEntries: 16,
            maxArchiveBytes: 1_000_000,
            maxArchiveCompressionRatio: 100,
            maxTargetBytes: null);
        SourceFile? layerFile = files.FirstOrDefault(static file => file.DisplayPath.Equals(
            "oci-archive/image-zstd.tar!blobs/sha256/layer!etc/zstd-secret.conf",
            StringComparison.Ordinal));

        Assert.IsNotNull(layerFile);
        Assert.AreEqual("token-zstd-12345", Encoding.UTF8.GetString(layerFile.ReadAllBytes()));
    }

    /// <summary>
    /// Verifies that archive traversal can be disabled for container image archives.
    /// </summary>
    [TestMethod]
    public void EnumerateHonorsDisabledArchiveDepth()
    {
        using TempDirectory temp = TempDirectory.Create();
        string archivePath = Path.Combine(temp.Path, "image.tar");
        File.WriteAllBytes(
            archivePath,
            TarTestData.CreateTarBytes(("manifest.json", Encoding.UTF8.GetBytes("[]"))));

        List<SourceFile> files = ContainerArchiveSource.Enumerate(
            archivePath,
            "docker-archive",
            maxArchiveDepth: 0,
            maxArchiveEntries: 16,
            maxArchiveBytes: 1_000_000,
            maxArchiveCompressionRatio: 100,
            maxTargetBytes: null);

        Assert.IsEmpty(files);
    }

    private static byte[] CreateZstandardBytes(byte[] content)
    {
        using var stream = new MemoryStream();
        using (var compressionStream = new CompressionStream(stream, leaveOpen: true))
        {
            compressionStream.Write(content);
        }

        return stream.ToArray();
    }
}
