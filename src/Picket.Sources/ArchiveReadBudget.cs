using System.Globalization;

namespace Picket.Sources;

internal sealed class ArchiveReadBudget(int maxEntries, long? maxBytes, Action<string>? warningSink)
{
    internal int MaxEntries { get; } = maxEntries;

    internal long MaxBytes { get; } = maxBytes.GetValueOrDefault();

    internal int EntryCount { get; private set; }

    internal long ByteCount { get; private set; }

    internal bool EntryLimitReported { get; private set; }

    internal bool ByteLimitReported { get; private set; }

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

        ReportEntryLimit(archivePath);
        return false;
    }

    internal bool TryConsumeBytes(string archivePath, int byteCount)
    {
        return TryConsumeBytesCore(archivePath, byteCount);
    }

    internal bool TryReserveBytes(string archivePath, long byteCount)
    {
        return TryConsumeBytesCore(archivePath, byteCount);
    }

    private bool TryConsumeBytesCore(string archivePath, long byteCount)
    {
        if (MaxBytes == 0 || byteCount == 0)
        {
            return true;
        }

        long projectedByteCount = long.MaxValue - ByteCount < byteCount
            ? long.MaxValue
            : ByteCount + byteCount;
        if (projectedByteCount <= MaxBytes)
        {
            ByteCount = projectedByteCount;
            return true;
        }

        ReportByteLimit(archivePath, projectedByteCount);
        return false;
    }

    private void ReportEntryLimit(string archivePath)
    {
        if (EntryLimitReported)
        {
            return;
        }

        warningSink?.Invoke($"archive entry limit reached after {MaxEntries} entries while reading {archivePath}");
        EntryLimitReported = true;
    }

    private void ReportByteLimit(string archivePath, long projectedByteCount)
    {
        if (ByteLimitReported)
        {
            return;
        }

        warningSink?.Invoke(string.Concat(
            "archive byte limit reached while reading ",
            archivePath,
            ": ",
            projectedByteCount.ToString(CultureInfo.InvariantCulture),
            " bytes would exceed ",
            MaxBytes.ToString(CultureInfo.InvariantCulture),
            " bytes"));
        ByteLimitReported = true;
    }
}
