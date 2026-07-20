using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Verifies bounded probing of non-seekable scan inputs.
/// </summary>
[TestClass]
public sealed class MaxLengthReadStreamTests
{
    /// <summary>
    /// Verifies that an over-limit input exposes only the single byte needed to detect overflow.
    /// </summary>
    [TestMethod]
    public void ReadStopsAfterOverflowProbe()
    {
        using var inner = new MemoryStream([1, 2, 3, 4, 5, 6]);
        using var stream = new MaxLengthReadStream(inner, 3);
        byte[] buffer = new byte[16];

        int firstRead = stream.Read(buffer);
        int secondRead = stream.Read(buffer);

        Assert.AreEqual(4, firstRead);
        Assert.AreEqual(0, secondRead);
        Assert.IsTrue(stream.LimitExceeded);
        CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, buffer[..firstRead]);
    }

    /// <summary>
    /// Verifies that an input ending at the limit is accepted.
    /// </summary>
    [TestMethod]
    public void ReadAcceptsInputAtLimit()
    {
        using var inner = new MemoryStream([1, 2, 3]);
        using var stream = new MaxLengthReadStream(inner, 3);
        byte[] buffer = new byte[8];

        int firstRead = stream.Read(buffer);
        int secondRead = stream.Read(buffer);

        Assert.AreEqual(3, firstRead);
        Assert.AreEqual(0, secondRead);
        Assert.IsFalse(stream.LimitExceeded);
    }
}
