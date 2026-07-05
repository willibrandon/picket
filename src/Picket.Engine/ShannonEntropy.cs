namespace Picket.Engine;

/// <summary>
/// Computes Shannon entropy over byte data.
/// </summary>
public static class ShannonEntropy
{
    /// <summary>
    /// Calculates Shannon entropy for a byte span.
    /// </summary>
    public static double Calculate(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte value in bytes)
        {
            counts[value]++;
        }

        double entropy = 0;
        double length = bytes.Length;
        for (int i = 0; i < counts.Length; i++)
        {
            int count = counts[i];
            if (count == 0)
            {
                continue;
            }

            double probability = count / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
