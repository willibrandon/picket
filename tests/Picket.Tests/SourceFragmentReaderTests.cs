using Picket.Sources;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Verifies bounded source fragment reading and position tracking.
/// </summary>
[TestClass]
public sealed class SourceFragmentReaderTests
{
    /// <summary>
    /// Verifies that the reader extends a primary fragment through a blank-line boundary.
    /// </summary>
    [TestMethod]
    public void ReadNextExtendsThroughSafeBoundary()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("abcde\n\nfghij"));
        using var reader = new SourceFragmentReader(stream, bufferSize: 5, maxPeekBytes: 20, leaveOpen: true);

        using SourceFragment first = reader.ReadNext(TestContext.CancellationToken)!;
        using SourceFragment second = reader.ReadNext(TestContext.CancellationToken)!;
        SourceFragment? end = reader.ReadNext(TestContext.CancellationToken);

        Assert.AreEqual("abcde\n\n", Encoding.UTF8.GetString(first.Content.Span));
        Assert.AreEqual(0, first.StartOffset);
        Assert.AreEqual(1, first.StartLine);
        Assert.AreEqual(1, first.StartColumn);
        Assert.AreEqual("fghij", Encoding.UTF8.GetString(second.Content.Span));
        Assert.AreEqual(7, second.StartOffset);
        Assert.AreEqual(3, second.StartLine);
        Assert.AreEqual(1, second.StartColumn);
        Assert.IsNull(end);
        Assert.IsTrue(stream.CanRead);
    }

    /// <summary>
    /// Verifies that a newline at the primary boundary contributes to the safe-boundary pair.
    /// </summary>
    [TestMethod]
    public void ReadNextCarriesTrailingNewlineIntoReadAhead()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("abcd\n\nnext"));
        using var reader = new SourceFragmentReader(stream, bufferSize: 5, maxPeekBytes: 5);

        using SourceFragment first = reader.ReadNext(TestContext.CancellationToken)!;
        using SourceFragment second = reader.ReadNext(TestContext.CancellationToken)!;

        Assert.AreEqual("abcd\n\n", Encoding.UTF8.GetString(first.Content.Span));
        Assert.AreEqual("next", Encoding.UTF8.GetString(second.Content.Span));
    }

    /// <summary>
    /// Verifies that a hard fragment boundary preserves the next fragment's original column.
    /// </summary>
    [TestMethod]
    public void ReadNextTracksColumnAcrossHardBoundary()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("abcdefghijkl\nx"));
        using var reader = new SourceFragmentReader(stream, bufferSize: 5, maxPeekBytes: 2);

        using SourceFragment first = reader.ReadNext(TestContext.CancellationToken)!;
        using SourceFragment second = reader.ReadNext(TestContext.CancellationToken)!;

        Assert.AreEqual("abcdefg", Encoding.UTF8.GetString(first.Content.Span));
        Assert.AreEqual("hijkl\nx", Encoding.UTF8.GetString(second.Content.Span));
        Assert.AreEqual(7, second.StartOffset);
        Assert.AreEqual(1, second.StartLine);
        Assert.AreEqual(8, second.StartColumn);
    }

    /// <summary>
    /// Verifies that a fragment beginning after a newline starts on the next source line.
    /// </summary>
    [TestMethod]
    public void ReadNextTracksLineAcrossHardBoundary()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("abcd\nxy"));
        using var reader = new SourceFragmentReader(stream, bufferSize: 5, maxPeekBytes: 0);

        using SourceFragment first = reader.ReadNext(TestContext.CancellationToken)!;
        using SourceFragment second = reader.ReadNext(TestContext.CancellationToken)!;

        Assert.AreEqual("abcd\n", Encoding.UTF8.GetString(first.Content.Span));
        Assert.AreEqual("xy", Encoding.UTF8.GetString(second.Content.Span));
        Assert.AreEqual(5, second.StartOffset);
        Assert.AreEqual(2, second.StartLine);
        Assert.AreEqual(1, second.StartColumn);
    }

    /// <summary>
    /// Verifies that cancellation is observed before another fragment is read.
    /// </summary>
    [TestMethod]
    public void ReadNextObservesCancellation()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("content"));
        using var reader = new SourceFragmentReader(stream);
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsExactly<OperationCanceledException>(() => reader.ReadNext(cancellationTokenSource.Token));
    }

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;
}
