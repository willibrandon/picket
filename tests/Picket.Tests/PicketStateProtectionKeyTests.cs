using Picket.Store;

namespace Picket.Tests;

/// <summary>
/// Tests state-protection key persistence.
/// </summary>
[TestClass]
public sealed class PicketStateProtectionKeyTests
{
    /// <summary>
    /// Gets or sets the test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies concurrent callers repair a malformed key without observing different replacements.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task LoadOrCreatePathRepairsMalformedKeyOnceAcrossConcurrentCallers()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");
        File.WriteAllBytes(keyPath, [0x01]);
        using var start = new ManualResetEventSlim();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var tasks = new Task<byte[]>[32];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                start.Wait(cancellationToken);
                return PicketStateProtectionKey.LoadOrCreatePath(keyPath);
            }, cancellationToken);
        }

        start.Set();
        byte[][] keys = await Task.WhenAll(tasks).ConfigureAwait(false);

        Assert.HasCount(tasks.Length, keys);
        Assert.HasCount(32, keys[0]);
        for (int i = 1; i < keys.Length; i++)
        {
            CollectionAssert.AreEqual(keys[0], keys[i]);
        }

        CollectionAssert.AreEqual(keys[0], File.ReadAllBytes(keyPath));
    }
}
