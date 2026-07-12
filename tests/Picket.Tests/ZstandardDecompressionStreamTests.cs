using Picket.Sources;
using System.Text;
using ZstdSharp;

namespace Picket.Tests;

/// <summary>
/// Covers bounded zstandard stream decompression used by archive scanning.
/// </summary>
[TestClass]
public sealed class ZstandardDecompressionStreamTests
{
    private static readonly byte[] s_frameRequiring128MiBWindow = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x88, 0x01, 0x00, 0x00];

    /// <summary>
    /// Verifies that a complete zstandard frame is decompressed.
    /// </summary>
    [TestMethod]
    public void ReadDecompressesCompleteFrame()
    {
        byte[] expected = Encoding.UTF8.GetBytes("zstandard fixture");
        byte[] compressed = Compress(expected);
        using var input = new MemoryStream(compressed, writable: false);
        using var stream = new ZstandardDecompressionStream(input, maximumWindowBytes: null, leaveOpen: false);
        using var output = new MemoryStream();

        stream.CopyTo(output);

        CollectionAssert.AreEqual(expected, output.ToArray());
    }

    /// <summary>
    /// Verifies that concatenated zstandard frames are decompressed in order.
    /// </summary>
    [TestMethod]
    public void ReadDecompressesConcatenatedFrames()
    {
        byte[] first = Compress(Encoding.UTF8.GetBytes("first"));
        byte[] second = Compress(Encoding.UTF8.GetBytes("second"));
        using var input = new MemoryStream([.. first, .. second], writable: false);
        using var stream = new ZstandardDecompressionStream(input, maximumWindowBytes: null, leaveOpen: false);
        using var output = new MemoryStream();

        stream.CopyTo(output);

        Assert.AreEqual("firstsecond", Encoding.UTF8.GetString(output.ToArray()));
    }

    /// <summary>
    /// Verifies that truncated zstandard frames are rejected.
    /// </summary>
    [TestMethod]
    public void ReadRejectsTruncatedFrame()
    {
        byte[] compressed = Compress(Encoding.UTF8.GetBytes("truncated zstandard fixture"));
        using var input = new MemoryStream(compressed[..^1], writable: false);
        using var stream = new ZstandardDecompressionStream(input, maximumWindowBytes: null, leaveOpen: false);
        using var output = new MemoryStream();

        Assert.Throws<InvalidDataException>(() => stream.CopyTo(output));
    }

    /// <summary>
    /// Verifies the default decoder limit refuses frames requiring a 128 MiB window.
    /// </summary>
    [TestMethod]
    public void ReadRejectsFrameExceedingDefaultWindowLimit()
    {
        using var input = new MemoryStream(s_frameRequiring128MiBWindow, writable: false);
        using var stream = new ZstandardDecompressionStream(input, maximumWindowBytes: null, leaveOpen: false);

        Assert.Throws<InvalidDataException>(() => stream.ReadByte());
    }

    /// <summary>
    /// Verifies disposal is idempotent and subsequent reads fail predictably.
    /// </summary>
    [TestMethod]
    public void DisposeIsIdempotentAndReadAfterDisposeThrows()
    {
        using var input = new MemoryStream(Compress(Encoding.UTF8.GetBytes("content")), writable: false);
        var stream = new ZstandardDecompressionStream(input, maximumWindowBytes: null, leaveOpen: true);

        stream.Dispose();
        stream.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => stream.ReadByte());
    }

    private static byte[] Compress(byte[] content)
    {
        using var stream = new MemoryStream();
        using (var compressionStream = new CompressionStream(stream, leaveOpen: true))
        {
            compressionStream.Write(content);
        }

        return stream.ToArray();
    }
}
