using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests scan worker selection from work, CPU, and memory limits.
/// </summary>
[TestClass]
public sealed class ScanParallelismPolicyTests
{
    /// <summary>
    /// Verifies that small workloads avoid parallel scheduling overhead.
    /// </summary>
    [TestMethod]
    public void CalculateUsesOneWorkerForSmallWorkloads()
    {
        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 7,
            processorCount: 32,
            memoryLoadBytes: 0,
            highMemoryLoadThresholdBytes: 8 * 1024 * 1024 * 1024L);

        Assert.AreEqual(1, decision.WorkerCount);
    }

    /// <summary>
    /// Verifies that a single effective processor always uses one worker.
    /// </summary>
    [TestMethod]
    public void CalculateUsesOneWorkerForOneProcessor()
    {
        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 1,
            memoryLoadBytes: 0,
            highMemoryLoadThresholdBytes: 8 * 1024 * 1024 * 1024L);

        Assert.AreEqual(1, decision.WorkerCount);
        Assert.AreEqual(1, decision.EffectiveProcessorCount);
    }

    /// <summary>
    /// Verifies that available work limits the worker count.
    /// </summary>
    [TestMethod]
    public void CalculateCapsWorkersByWorkItemCount()
    {
        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 12,
            processorCount: 24,
            memoryLoadBytes: 0,
            highMemoryLoadThresholdBytes: 8 * 1024 * 1024 * 1024L);

        Assert.AreEqual(12, decision.WorkerCount);
    }

    /// <summary>
    /// Verifies that sufficient absolute headroom keeps all processors available at high relative pressure.
    /// </summary>
    [TestMethod]
    public void CalculateKeepsProcessorsWhenAbsoluteHeadroomIsSufficient()
    {
        const long GiB = 1024L * 1024 * 1024;

        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 24,
            memoryLoadBytes: 38 * GiB,
            highMemoryLoadThresholdBytes: 40 * GiB);

        Assert.AreEqual(24, decision.WorkerCount);
        Assert.AreEqual(2 * GiB, decision.MemoryHeadroomBytes);
    }

    /// <summary>
    /// Verifies that absolute headroom limits workers by the per-worker memory budget.
    /// </summary>
    [TestMethod]
    public void CalculateCapsWorkersByMemoryHeadroom()
    {
        long headroomBytes = 4 * ScanParallelismPolicy.MemoryBudgetPerWorkerBytes;

        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 24,
            memoryLoadBytes: 8 * 1024 * 1024 * 1024L - headroomBytes,
            highMemoryLoadThresholdBytes: 8 * 1024 * 1024 * 1024L);

        Assert.AreEqual(4, decision.WorkerCount);
        Assert.AreEqual(headroomBytes, decision.MemoryHeadroomBytes);
    }

    /// <summary>
    /// Verifies that less than one worker budget still permits forward progress.
    /// </summary>
    [TestMethod]
    public void CalculateUsesOneWorkerBelowMemoryBudget()
    {
        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 24,
            memoryLoadBytes: 8 * 1024 * 1024 * 1024L - ScanParallelismPolicy.MemoryBudgetPerWorkerBytes + 1,
            highMemoryLoadThresholdBytes: 8 * 1024 * 1024 * 1024L);

        Assert.AreEqual(1, decision.WorkerCount);
    }

    /// <summary>
    /// Verifies that no headroom above the GC high-memory threshold uses one worker.
    /// </summary>
    [TestMethod]
    public void CalculateUsesOneWorkerWithoutMemoryHeadroom()
    {
        const long ThresholdBytes = 8 * 1024 * 1024 * 1024L;

        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 24,
            memoryLoadBytes: ThresholdBytes,
            highMemoryLoadThresholdBytes: ThresholdBytes);

        Assert.AreEqual(1, decision.WorkerCount);
        Assert.AreEqual(0, decision.MemoryHeadroomBytes);
    }

    /// <summary>
    /// Verifies that unavailable GC memory metrics retain the CPU-based fallback.
    /// </summary>
    [TestMethod]
    public void CalculateFallsBackToProcessorCountWithoutMemoryMetrics()
    {
        ScanParallelismDecision decision = ScanParallelismPolicy.Calculate(
            workItemCount: 100,
            processorCount: 24,
            memoryLoadBytes: 0,
            highMemoryLoadThresholdBytes: 0);

        Assert.AreEqual(24, decision.WorkerCount);
        Assert.AreEqual(0, decision.MemoryHeadroomBytes);
    }
}
