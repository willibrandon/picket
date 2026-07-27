namespace Picket;

internal sealed class CompatibilityScanMetrics
{
    private long _totalBytes;

    internal long TotalBytes => Interlocked.Read(ref _totalBytes);

    internal void AddBytes(long count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        Interlocked.Add(ref _totalBytes, count);
    }
}
