namespace Picket.Sources;

internal readonly struct ScanParallelismDecision
{
    internal ScanParallelismDecision(
        int workerCount,
        int effectiveProcessorCount,
        long memoryLoadBytes,
        long highMemoryLoadThresholdBytes,
        long memoryHeadroomBytes)
    {
        WorkerCount = workerCount;
        EffectiveProcessorCount = effectiveProcessorCount;
        MemoryLoadBytes = memoryLoadBytes;
        HighMemoryLoadThresholdBytes = highMemoryLoadThresholdBytes;
        MemoryHeadroomBytes = memoryHeadroomBytes;
    }

    internal int WorkerCount { get; }

    internal int EffectiveProcessorCount { get; }

    internal long MemoryLoadBytes { get; }

    internal long HighMemoryLoadThresholdBytes { get; }

    internal long MemoryHeadroomBytes { get; }
}
