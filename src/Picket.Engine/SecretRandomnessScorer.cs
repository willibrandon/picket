using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Unicode;

namespace Picket.Engine;

/// <summary>
/// Scores whether byte-oriented secret material resembles a uniformly generated token.
/// </summary>
public static class SecretRandomnessScorer
{
    /// <summary>
    /// Identifies the coefficients, feature definitions, and calibration corpus used by this model.
    /// </summary>
    public const string ModelVersion = "picket-random-v1";

    /// <summary>
    /// Gets the inclusive score threshold classified as likely random.
    /// </summary>
    public const double LikelyRandomThreshold = 0.8;

    /// <summary>
    /// Gets the inclusive score threshold classified as likely structured.
    /// </summary>
    public const double LikelyStructuredThreshold = 0.2;

    private const string AlphanumericAlphabet = "alphanumeric";
    private const string ByteAlphabet = "bytes";
    private const string HexAlphabet = "hex";
    private const int MinimumTokenSampleLength = 4;
    private const int MaximumCandidateInspectionLength = 4096;
    private const int MaximumTokenSampleLength = 512;

    // Coefficients are regenerated and verified by scripts/Calibrate-RandomnessModel.cs.
    private const double Intercept = -7.8723183968631716;
    private const double LengthWeight = 2.2867492630181623;
    private const double NormalizedEntropyWeight = 0.6140012917520794;
    private const double ExpectedDistinctWeight = 2.6765546170578518;
    private const double TransitionDiversityWeight = 1.1562954323571997;
    private const double LongestRunWeight = -0.5343608704226237;
    private const double SequentialPairWeight = -2.829404791383813;
    private const double RepeatedPatternWeight = -1.643366679536477;
    private const double CommonBigramWeight = -2.4778590005602474;
    private const double CharacterClassBalanceWeight = 5.1687411338760532;
    private const double EncodedTextWeight = -3.4148003163772298;
    private const double PlaceholderWeight = -1.6595559422126624;

    /// <summary>
    /// Assesses UTF-16 secret text after deterministic UTF-8 encoding.
    /// </summary>
    /// <param name="value">The secret text to assess.</param>
    /// <returns>The randomness assessment.</returns>
    public static SecretRandomnessAssessment Assess(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Span<byte> encoded = stackalloc byte[MaximumCandidateInspectionLength];
        int bytesUsed = 0;
        try
        {
            _ = Utf8.FromUtf16(
                value.AsSpan(),
                encoded,
                out _,
                out bytesUsed,
                replaceInvalidSequences: true,
                isFinalBlock: true);
            return Assess(encoded[..bytesUsed]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded[..bytesUsed]);
        }
    }

    /// <summary>
    /// Assesses byte-oriented secret material.
    /// </summary>
    /// <param name="value">The secret bytes to assess.</param>
    /// <returns>The randomness assessment.</returns>
    public static SecretRandomnessAssessment Assess(ReadOnlySpan<byte> value)
    {
        SecretRandomnessFeatures features = ExtractFeatures(value);
        if (features.SampleLength == 0)
        {
            return new SecretRandomnessAssessment(
                ModelVersion,
                0,
                "likely-structured",
                features,
                CreateSignals(features));
        }

        double linearScore = Intercept
            + (LengthWeight * features.LengthScore)
            + (NormalizedEntropyWeight * features.NormalizedEntropy)
            + (ExpectedDistinctWeight * features.ExpectedDistinctRatio)
            + (TransitionDiversityWeight * features.TransitionDiversity)
            + (LongestRunWeight * features.LongestRunRatio)
            + (SequentialPairWeight * features.SequentialPairRatio)
            + (RepeatedPatternWeight * features.RepeatedPatternRatio)
            + (CommonBigramWeight * features.CommonBigramRatio)
            + (CharacterClassBalanceWeight * features.CharacterClassBalance)
            + (EncodedTextWeight * features.EncodedTextSignal)
            + (PlaceholderWeight * features.PlaceholderSignal);
        double score = Quantize(1 / (1 + Math.Exp(-linearScore)));
        string classification = score >= LikelyRandomThreshold
            ? "likely-random"
            : score <= LikelyStructuredThreshold ? "likely-structured" : "indeterminate";

        return new SecretRandomnessAssessment(
            ModelVersion,
            score,
            classification,
            features,
            CreateSignals(features));
    }

    /// <summary>
    /// Extracts the non-secret feature vector used by the randomness model.
    /// </summary>
    /// <param name="value">The secret bytes to inspect.</param>
    /// <returns>The extracted feature vector.</returns>
    public static SecretRandomnessFeatures ExtractFeatures(ReadOnlySpan<byte> value)
    {
        FindTokenSample(value, out int sampleOffset, out int sampleLength);
        ReadOnlySpan<byte> sample = value.Slice(sampleOffset, sampleLength);
        if (sample.IsEmpty)
        {
            return new SecretRandomnessFeatures(0, 0, ByteAlphabet, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }

        Span<int> byteCounts = stackalloc int[256];
        Span<ulong> transitionBits = stackalloc ulong[1024];
        byteCounts.Clear();
        transitionBits.Clear();
        int distinctCount = 0;
        int distinctTransitions = 0;
        int longestRun = 1;
        int currentRun = 1;
        int sequentialPairs = 0;
        int commonBigrams = 0;
        int uppercaseCount = 0;
        int lowercaseCount = 0;
        int digitCount = 0;

        for (int i = 0; i < sample.Length; i++)
        {
            byte current = sample[i];
            if (byteCounts[current]++ == 0)
            {
                distinctCount++;
            }

            if (current is >= (byte)'A' and <= (byte)'Z')
            {
                uppercaseCount++;
            }
            else if (current is >= (byte)'a' and <= (byte)'z')
            {
                lowercaseCount++;
            }
            else if (current is >= (byte)'0' and <= (byte)'9')
            {
                digitCount++;
            }

            if (i == 0)
            {
                continue;
            }

            byte previous = sample[i - 1];
            int pair = (previous << 8) | current;
            int wordIndex = pair >> 6;
            ulong mask = 1UL << (pair & 63);
            if ((transitionBits[wordIndex] & mask) == 0)
            {
                transitionBits[wordIndex] |= mask;
                distinctTransitions++;
            }

            if (current == previous)
            {
                currentRun++;
                longestRun = Math.Max(longestRun, currentRun);
            }
            else
            {
                currentRun = 1;
            }

            if (IsSequentialPair(previous, current))
            {
                sequentialPairs++;
            }

            if (IsCommonBigram(previous, current))
            {
                commonBigrams++;
            }
        }

        bool isHex = IsHex(sample);
        string alphabet = isHex ? HexAlphabet : IsAsciiAlphanumeric(sample) ? AlphanumericAlphabet : ByteAlphabet;
        int alphabetSize = isHex ? 16 : alphabet == AlphanumericAlphabet ? 62 : 256;
        double entropyDenominator = Math.Log2(Math.Min(alphabetSize, sample.Length));
        double normalizedEntropy = entropyDenominator == 0
            ? 0
            : Math.Clamp(ShannonEntropy.Calculate(sample) / entropyDenominator, 0, 1);
        double expectedDistinct = alphabetSize * (1 - Math.Pow((alphabetSize - 1d) / alphabetSize, sample.Length));
        int pairCount = Math.Max(1, sample.Length - 1);

        return new SecretRandomnessFeatures(
            sampleOffset,
            sample.Length,
            alphabet,
            Quantize(Math.Min(1, Math.Log2(sample.Length + 1) / 7)),
            Quantize(normalizedEntropy),
            Quantize(Math.Min(1, distinctCount / expectedDistinct)),
            Quantize(distinctTransitions / (double)pairCount),
            Quantize(longestRun / (double)sample.Length),
            Quantize(sequentialPairs / (double)pairCount),
            Quantize(CreateRepeatedPatternRatio(sample)),
            Quantize(commonBigrams / (double)pairCount),
            Quantize(CreateCharacterClassBalance(sample.Length, alphabet, uppercaseCount, lowercaseCount, digitCount)),
            Quantize(CreateEncodedTextSignal(sample)),
            ContainsPlaceholder(sample) ? 1 : 0);
    }

    private static List<string> CreateSignals(SecretRandomnessFeatures features)
    {
        var signals = new List<string>(11);
        if (features.SampleLength < 12)
        {
            signals.Add("short-sample");
        }

        if (features.NormalizedEntropy >= 0.9)
        {
            signals.Add("high-normalized-entropy");
        }

        if (features.ExpectedDistinctRatio >= 0.9)
        {
            signals.Add("uniform-distinctness");
        }

        if (features.TransitionDiversity >= 0.9)
        {
            signals.Add("diverse-transitions");
        }

        if (features.CharacterClassBalance >= 0.8)
        {
            signals.Add("balanced-character-classes");
        }

        if (features.LongestRunRatio >= 0.25)
        {
            signals.Add("repeated-run");
        }

        if (features.SequentialPairRatio >= 0.2)
        {
            signals.Add("sequential-pattern");
        }

        if (features.RepeatedPatternRatio >= 0.35)
        {
            signals.Add("periodic-pattern");
        }

        if (features.CommonBigramRatio >= 0.3)
        {
            signals.Add("language-like-bigrams");
        }

        if (features.EncodedTextSignal >= 0.5)
        {
            signals.Add("encoded-printable-text");
        }

        if (features.PlaceholderSignal != 0)
        {
            signals.Add("placeholder-marker");
        }

        return signals;
    }

    private static double CreateCharacterClassBalance(
        int length,
        string alphabet,
        int uppercaseCount,
        int lowercaseCount,
        int digitCount)
    {
        if (alphabet == HexAlphabet)
        {
            double observedDigits = digitCount / (double)length;
            return 1 - Math.Abs(observedDigits - (10d / 16));
        }

        if (alphabet == AlphanumericAlphabet)
        {
            double observedUppercase = uppercaseCount / (double)length;
            double observedLowercase = lowercaseCount / (double)length;
            double observedDigits = digitCount / (double)length;
            double totalVariation = 0.5 * (
                Math.Abs(observedUppercase - (26d / 62))
                + Math.Abs(observedLowercase - (26d / 62))
                + Math.Abs(observedDigits - (10d / 62)));
            return Math.Clamp(1 - totalVariation, 0, 1);
        }

        return 0.5;
    }

    private static double CreateRepeatedPatternRatio(ReadOnlySpan<byte> sample)
    {
        double strongestRatio = 0;
        int maximumPeriod = Math.Min(8, sample.Length / 2);
        for (int period = 1; period <= maximumPeriod; period++)
        {
            int matches = 0;
            for (int i = period; i < sample.Length; i++)
            {
                if (sample[i] == sample[i - period])
                {
                    matches++;
                }
            }

            strongestRatio = Math.Max(strongestRatio, matches / (double)(sample.Length - period));
        }

        return strongestRatio;
    }

    private static double CreateEncodedTextSignal(ReadOnlySpan<byte> sample)
    {
        if (sample.Length < 12 || sample.Length > MaximumTokenSampleLength || (sample.Length & 3) == 1)
        {
            return 0;
        }

        int paddingLength = (4 - (sample.Length & 3)) & 3;
        Span<byte> padded = stackalloc byte[MaximumTokenSampleLength + 3];
        sample.CopyTo(padded);
        padded.Slice(sample.Length, paddingLength).Fill((byte)'=');
        Span<byte> decoded = stackalloc byte[((MaximumTokenSampleLength + 3) / 4) * 3];
        OperationStatus status = Base64.DecodeFromUtf8(
            padded[..(sample.Length + paddingLength)],
            decoded,
            out _,
            out int bytesWritten,
            isFinalBlock: true);
        if (status != OperationStatus.Done || bytesWritten < 8)
        {
            CryptographicOperations.ZeroMemory(padded[..(sample.Length + paddingLength)]);
            CryptographicOperations.ZeroMemory(decoded[..bytesWritten]);
            return 0;
        }

        int printableCount = 0;
        int textCount = 0;
        for (int i = 0; i < bytesWritten; i++)
        {
            byte value = decoded[i];
            if (value is (byte)'\t' or (byte)'\n' or (byte)'\r' or >= 0x20 and <= 0x7E)
            {
                printableCount++;
            }

            if (value is (byte)' ' or (byte)'_' or (byte)'-'
                or >= (byte)'A' and <= (byte)'Z'
                or >= (byte)'a' and <= (byte)'z')
            {
                textCount++;
            }
        }

        double printableRatio = printableCount / (double)bytesWritten;
        double textRatio = textCount / (double)bytesWritten;
        double signal = Math.Clamp((printableRatio - 0.65) / 0.35, 0, 1)
            * Math.Clamp((textRatio - 0.5) / 0.5, 0, 1);
        CryptographicOperations.ZeroMemory(padded[..(sample.Length + paddingLength)]);
        CryptographicOperations.ZeroMemory(decoded[..bytesWritten]);
        return signal;
    }

    private static void FindTokenSample(ReadOnlySpan<byte> value, out int offset, out int length)
    {
        ReadOnlySpan<byte> inspected = value[..Math.Min(value.Length, MaximumCandidateInspectionLength)];
        offset = 0;
        length = Math.Min(inspected.Length, MaximumTokenSampleLength);
        int bestOffset = 0;
        int bestLength = 0;
        int currentOffset = 0;
        int currentLength = 0;
        for (int i = 0; i <= inspected.Length; i++)
        {
            if (i < inspected.Length && IsAsciiLetterOrDigit(inspected[i]))
            {
                if (currentLength == 0)
                {
                    currentOffset = i;
                }

                currentLength++;
                continue;
            }

            if (currentLength > bestLength)
            {
                bestOffset = currentOffset;
                bestLength = currentLength;
            }

            currentLength = 0;
        }

        if (bestLength >= MinimumTokenSampleLength)
        {
            offset = bestOffset;
            length = Math.Min(bestLength, MaximumTokenSampleLength);
        }
    }

    private static bool ContainsPlaceholder(ReadOnlySpan<byte> sample)
    {
        return ContainsAsciiIgnoreCase(sample, "placeholder"u8)
            || ContainsAsciiIgnoreCase(sample, "example"u8)
            || ContainsAsciiIgnoreCase(sample, "sample"u8)
            || ContainsAsciiIgnoreCase(sample, "dummy"u8)
            || ContainsAsciiIgnoreCase(sample, "changeme"u8)
            || ContainsAsciiIgnoreCase(sample, "password"u8)
            || ContainsAsciiIgnoreCase(sample, "secret"u8)
            || ContainsAsciiIgnoreCase(sample, "token"u8)
            || ContainsAsciiIgnoreCase(sample, "apikey"u8)
            || ContainsAsciiIgnoreCase(sample, "undefined"u8)
            || ContainsAsciiIgnoreCase(sample, "localhost"u8);
    }

    private static bool ContainsAsciiIgnoreCase(ReadOnlySpan<byte> value, ReadOnlySpan<byte> candidate)
    {
        if (candidate.Length > value.Length)
        {
            return false;
        }

        for (int start = 0; start <= value.Length - candidate.Length; start++)
        {
            bool matched = true;
            for (int i = 0; i < candidate.Length; i++)
            {
                if (ToAsciiLower(value[start + i]) != candidate[i])
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAsciiAlphanumeric(ReadOnlySpan<byte> sample)
    {
        foreach (byte value in sample)
        {
            if (!IsAsciiLetterOrDigit(value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHex(ReadOnlySpan<byte> sample)
    {
        foreach (byte value in sample)
        {
            if (!((value is >= (byte)'0' and <= (byte)'9')
                || (value is >= (byte)'A' and <= (byte)'F')
                || (value is >= (byte)'a' and <= (byte)'f')))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiLetterOrDigit(byte value)
    {
        return value is >= (byte)'0' and <= (byte)'9'
            or >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z';
    }

    private static bool IsSequentialPair(byte first, byte second)
    {
        byte normalizedFirst = ToAsciiLower(first);
        byte normalizedSecond = ToAsciiLower(second);
        bool sameClass = (normalizedFirst is >= (byte)'a' and <= (byte)'z'
                && normalizedSecond is >= (byte)'a' and <= (byte)'z')
            || (normalizedFirst is >= (byte)'0' and <= (byte)'9'
                && normalizedSecond is >= (byte)'0' and <= (byte)'9');
        return sameClass && Math.Abs(normalizedFirst - normalizedSecond) == 1;
    }

    private static bool IsCommonBigram(byte first, byte second)
    {
        int pair = (ToAsciiLower(first) << 8) | ToAsciiLower(second);
        return pair == (('a' << 8) | 'l')
            || pair == (('a' << 8) | 'n')
            || pair == (('a' << 8) | 'r')
            || pair == (('a' << 8) | 's')
            || pair == (('a' << 8) | 't')
            || pair == (('c' << 8) | 'o')
            || pair == (('d' << 8) | 'e')
            || pair == (('e' << 8) | 'd')
            || pair == (('e' << 8) | 'n')
            || pair == (('e' << 8) | 'r')
            || pair == (('e' << 8) | 's')
            || pair == (('e' << 8) | 'y')
            || pair == (('h' << 8) | 'a')
            || pair == (('h' << 8) | 'e')
            || pair == (('i' << 8) | 'd')
            || pair == (('i' << 8) | 'n')
            || pair == (('i' << 8) | 'o')
            || pair == (('i' << 8) | 's')
            || pair == (('i' << 8) | 't')
            || pair == (('k' << 8) | 'e')
            || pair == (('l' << 8) | 'e')
            || pair == (('n' << 8) | 'd')
            || pair == (('n' << 8) | 'g')
            || pair == (('n' << 8) | 't')
            || pair == (('o' << 8) | 'f')
            || pair == (('o' << 8) | 'n')
            || pair == (('o' << 8) | 'r')
            || pair == (('o' << 8) | 'u')
            || pair == (('p' << 8) | 'a')
            || pair == (('r' << 8) | 'e')
            || pair == (('s' << 8) | 'e')
            || pair == (('s' << 8) | 't')
            || pair == (('t' << 8) | 'e')
            || pair == (('t' << 8) | 'h')
            || pair == (('t' << 8) | 'i')
            || pair == (('t' << 8) | 'o')
            || pair == (('v' << 8) | 'e');
    }

    private static byte ToAsciiLower(byte value)
    {
        return value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
    }

    private static double Quantize(double value)
    {
        return Math.Round(value, 6, MidpointRounding.AwayFromZero);
    }
}
