namespace Picket.Sources;

internal sealed class ArchiveReadBudget(int maxEntries, Action<string>? warningSink)
{
    internal int MaxEntries { get; } = maxEntries;

    internal int EntryCount { get; private set; }

    internal bool LimitReported { get; private set; }

    internal bool TryConsumeEntry(string archivePath)
    {
        if (MaxEntries == 0)
        {
            return true;
        }

        if (EntryCount < MaxEntries)
        {
            EntryCount++;
            return true;
        }

        ReportLimit(archivePath);
        return false;
    }

    private void ReportLimit(string archivePath)
    {
        if (LimitReported)
        {
            return;
        }

        warningSink?.Invoke($"archive entry limit reached after {MaxEntries} entries while reading {archivePath}");
        LimitReported = true;
    }
}
