using Picket.Sources;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Verifies bounded BOM-directed UTF-16 stream transcoding.
/// </summary>
[TestClass]
public sealed class Utf16BomTranscodingStreamTests
{
    /// <summary>
    /// Verifies decoder state is preserved when encoded code units arrive one byte at a time.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void ReadTranscodesUtf16AcrossSourceReadBoundaries(bool bigEndian)
    {
        const string Content = "é 😀\ntoken-12345";
        byte[] sourceBytes = EncodeUtf16WithBom(Content, bigEndian);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var source = new ChunkedReadStream(new MemoryStream(sourceBytes), maximumReadLength: 1);
        using var transcoded = new Utf16BomTranscodingStream(source, hash, leaveOpen: true);

        byte[] output = ReadAllBytes(transcoded);

        Assert.AreEqual(Content, Encoding.UTF8.GetString(output));
        Assert.AreEqual(
            Convert.ToHexStringLower(SHA256.HashData(sourceBytes)),
            Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    /// <summary>
    /// Verifies input without a UTF-16 byte-order mark passes through unchanged.
    /// </summary>
    [TestMethod]
    public void ReadPreservesInputWithoutUtf16Bom()
    {
        byte[] sourceBytes = Encoding.UTF8.GetBytes("é token-12345");
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var source = new MemoryStream(sourceBytes);
        using var transcoded = new Utf16BomTranscodingStream(source, hash, leaveOpen: true);

        byte[] output = ReadAllBytes(transcoded);

        CollectionAssert.AreEqual(sourceBytes, output);
        Assert.AreEqual(
            Convert.ToHexStringLower(SHA256.HashData(sourceBytes)),
            Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    /// <summary>
    /// Verifies malformed trailing UTF-16 input is replaced rather than throwing.
    /// </summary>
    [TestMethod]
    public void ReadReplacesMalformedTrailingUtf16()
    {
        byte[] sourceBytes = [0xFF, 0xFE, 0x61, 0x00, 0xFF];
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var source = new MemoryStream(sourceBytes);
        using var transcoded = new Utf16BomTranscodingStream(source, hash, leaveOpen: true);

        byte[] output = ReadAllBytes(transcoded);

        Assert.AreEqual("a\uFFFD", Encoding.UTF8.GetString(output));
    }

    /// <summary>
    /// Verifies cancellation is observed before a fragment reads from the transcoding stream.
    /// </summary>
    [TestMethod]
    public void ReadNextObservesCancellationBeforeTranscoding()
    {
        byte[] sourceBytes = EncodeUtf16WithBom("token-12345", bigEndian: false);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var source = new MemoryStream(sourceBytes);
        using var transcoded = new Utf16BomTranscodingStream(source, hash, leaveOpen: true);
        using var reader = new SourceFragmentReader(transcoded, leaveOpen: true);
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsExactly<OperationCanceledException>(
            () => reader.ReadNext(cancellationTokenSource.Token));
    }

    private static byte[] EncodeUtf16WithBom(string value, bool bigEndian)
    {
        var encoding = new UnicodeEncoding(bigEndian, byteOrderMark: true, throwOnInvalidBytes: true);
        byte[] preamble = encoding.GetPreamble();
        byte[] content = encoding.GetBytes(value);
        var result = new byte[preamble.Length + content.Length];
        preamble.CopyTo(result, 0);
        content.CopyTo(result, preamble.Length);
        return result;
    }

    private static byte[] ReadAllBytes(Stream source)
    {
        using var destination = new MemoryStream();
        source.CopyTo(destination);
        return destination.ToArray();
    }
}
