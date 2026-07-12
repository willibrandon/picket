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

    /// <summary>
    /// Verifies key repair waits for a Windows reader that temporarily blocks atomic replacement.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    public async Task LoadOrCreatePathWaitsForTransientDestinationReader()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");
        File.WriteAllBytes(keyPath, [0x01]);
        CancellationToken cancellationToken = TestContext.CancellationToken;
        FileStream reader = File.Open(keyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Task<byte[]> repair = Task.Run(
            () => PicketStateProtectionKey.LoadOrCreatePath(keyPath),
            cancellationToken);
        try
        {
            bool tempFileObserved = false;
            for (int attempt = 0; attempt < 100; attempt++)
            {
                if (Directory.EnumerateFiles(temp.Path, "state.key.*.tmp").Any())
                {
                    tempFileObserved = true;
                    break;
                }

                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }

            Assert.IsTrue(tempFileObserved);
            Assert.IsFalse(repair.IsCompleted);
        }
        finally
        {
            reader.Dispose();
        }

        byte[] key = await repair.ConfigureAwait(false);

        Assert.HasCount(32, key);
        CollectionAssert.AreEqual(key, File.ReadAllBytes(keyPath));
    }
}
