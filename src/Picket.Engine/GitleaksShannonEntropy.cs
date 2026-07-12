using System.Buffers;
using System.Text;

namespace Picket.Engine;

internal static class GitleaksShannonEntropy
{
    internal static double Calculate(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return 0;
        }

        Span<int> asciiCounts = stackalloc int[128];
        Dictionary<int, int>? nonAsciiCounts = null;
        int offset = 0;
        while (offset < bytes.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(bytes[offset..], out Rune rune, out int consumed);
            if (status != OperationStatus.Done)
            {
                rune = Rune.ReplacementChar;
                consumed = 1;
            }

            if (rune.IsAscii)
            {
                asciiCounts[rune.Value]++;
            }
            else
            {
                nonAsciiCounts ??= [];
                nonAsciiCounts.TryGetValue(rune.Value, out int count);
                nonAsciiCounts[rune.Value] = count + 1;
            }

            offset += consumed;
        }

        double entropy = 0;
        double inverseByteLength = 1.0 / bytes.Length;
        for (int index = 0; index < asciiCounts.Length; index++)
        {
            int count = asciiCounts[index];
            if (count == 0)
            {
                continue;
            }

            double frequency = count * inverseByteLength;
            entropy -= frequency * Math.Log2(frequency);
        }

        if (nonAsciiCounts is not null)
        {
            foreach (int count in nonAsciiCounts.Values)
            {
                double frequency = count * inverseByteLength;
                entropy -= frequency * Math.Log2(frequency);
            }
        }

        return entropy;
    }
}
