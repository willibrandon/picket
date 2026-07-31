namespace Picket.Sources;

internal static class ScanParallelismPolicy
{
    internal const long MemoryBudgetPerWorkerBytes = 64L * 1024 * 1024;
    private const int MinimumParallelWorkItemCount = 8;

    internal static ScanParallelismDecision Create(int workItemCount)
    {
        GCMemoryInfo memoryInfo = GC.GetGCMemoryInfo();
        return Calculate(
            workItemCount,
            Environment.ProcessorCount,
            memoryInfo.MemoryLoadBytes,
            memoryInfo.HighMemoryLoadThresholdBytes);
    }

    internal static ScanParallelismDecision Calculate(
        int workItemCount,
        int processorCount,
        long memoryLoadBytes,
        long highMemoryLoadThresholdBytes)
    {
        int effectiveProcessorCount = Math.Max(1, processorCount);
        int processorDegree = Math.Min(Math.Max(1, workItemCount), effectiveProcessorCount);
        long memoryHeadroomBytes = highMemoryLoadThresholdBytes > 0
            ? Math.Max(0, highMemoryLoadThresholdBytes - Math.Max(0, memoryLoadBytes))
            : 0;

        int workerCount;
        if (workItemCount < MinimumParallelWorkItemCount || processorDegree <= 1)
        {
            workerCount = 1;
        }
        else if (highMemoryLoadThresholdBytes <= 0)
        {
            workerCount = processorDegree;
        }
        else
        {
            long memoryDegree = Math.Max(1, memoryHeadroomBytes / MemoryBudgetPerWorkerBytes);
            workerCount = (int)Math.Min(processorDegree, memoryDegree);
        }

        return new ScanParallelismDecision(
            workerCount,
            effectiveProcessorCount,
            Math.Max(0, memoryLoadBytes),
            Math.Max(0, highMemoryLoadThresholdBytes),
            memoryHeadroomBytes);
    }
}
