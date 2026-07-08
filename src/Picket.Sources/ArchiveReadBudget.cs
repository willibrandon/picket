using System.Globalization;

namespace Picket.Sources;

internal sealed class ArchiveReadBudget(
    int maxEntries,
    long? maxBytes,
    int maxCompressionRatio,
    Func<bool>? isCancellationRequested,
    Action<string>? warningSink)
{
    internal int MaxEntries { get; } = maxEntries;

    internal long MaxBytes { get; } = maxBytes.GetValueOrDefault();

    internal int MaxCompressionRatio { get; } = maxCompressionRatio;

    internal int EntryCount { get; private set; }

    internal long ByteCount { get; private set; }

    internal bool EntryLimitReported { get; private set; }

    internal bool ByteLimitReported { get; private set; }

    internal bool CompressionRatioLimitReported { get; private set; }

    internal bool CancellationReported { get; private set; }

    internal bool SizeMetadataMismatchReported { get; private set; }

    internal bool TryContinue(string archivePath)
    {
        if (isCancellationRequested is null || !isCancellationRequested())
        {
            return true;
        }

        ReportCancellation(archivePath);
        return false;
    }

    internal bool TryConsumeEntry(string archivePath)
    {
        if (!TryContinue(archivePath))
        {
            return false;
        }

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
        return TryConsumeBytesCore(archivePath, byteCount, consume: true);
    }

    internal bool TryCheckBytes(string archivePath, long byteCount)
    {
        return TryConsumeBytesCore(archivePath, byteCount, consume: false);
    }

    internal bool TryConsumeCompressionRatio(string archivePath, long compressedByteCount, long decompressedByteCount)
    {
        if (!TryContinue(archivePath))
        {
            return false;
        }

        if (MaxCompressionRatio == 0 || decompressedByteCount == 0)
        {
            return true;
        }

        if (compressedByteCount <= 0)
        {
            ReportCompressionRatioLimit(archivePath, compressedByteCount, decompressedByteCount);
            return false;
        }

        if (compressedByteCount <= long.MaxValue / MaxCompressionRatio
            && decompressedByteCount > compressedByteCount * MaxCompressionRatio)
        {
            ReportCompressionRatioLimit(archivePath, compressedByteCount, decompressedByteCount);
            return false;
        }

        return true;
    }

    internal void ReportSizeMetadataMismatch(string archivePath, long declaredByteCount, long actualByteCount)
    {
        if (SizeMetadataMismatchReported)
        {
            return;
        }

        warningSink?.Invoke(string.Concat(
            "archive size metadata mismatch while reading ",
            archivePath,
            ": ",
            actualByteCount.ToString(CultureInfo.InvariantCulture),
            " decompressed bytes exceeded declared ",
            declaredByteCount.ToString(CultureInfo.InvariantCulture),
            " bytes"));
        SizeMetadataMismatchReported = true;
    }

    private bool TryConsumeBytesCore(string archivePath, long byteCount, bool consume)
    {
        if (!TryContinue(archivePath))
        {
            return false;
        }

        if (MaxBytes == 0 || byteCount == 0)
        {
            return true;
        }

        long projectedByteCount = long.MaxValue - ByteCount < byteCount
            ? long.MaxValue
            : ByteCount + byteCount;
        if (projectedByteCount <= MaxBytes)
        {
            if (consume)
            {
                ByteCount = projectedByteCount;
            }

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

    private void ReportCompressionRatioLimit(string archivePath, long compressedByteCount, long decompressedByteCount)
    {
        if (CompressionRatioLimitReported)
        {
            return;
        }

        warningSink?.Invoke(string.Concat(
            "archive compression ratio limit reached while reading ",
            archivePath,
            ": ",
            decompressedByteCount.ToString(CultureInfo.InvariantCulture),
            " decompressed bytes from ",
            compressedByteCount.ToString(CultureInfo.InvariantCulture),
            " compressed bytes would exceed ",
            MaxCompressionRatio.ToString(CultureInfo.InvariantCulture),
            ":1"));
        CompressionRatioLimitReported = true;
    }

    private void ReportCancellation(string archivePath)
    {
        if (CancellationReported)
        {
            return;
        }

        warningSink?.Invoke($"archive read stopped because cancellation was requested while reading {archivePath}");
        CancellationReported = true;
    }
}
