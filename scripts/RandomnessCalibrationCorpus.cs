using Picket.Engine;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Creates the deterministic balanced corpus shared by native randomness model evaluations.
/// </summary>
internal static class RandomnessCalibrationCorpus
{
    /// <summary>The deterministic uniform alphabets represented by the calibration corpus.</summary>
    private static readonly string[] s_alphabets =
    [
        "0123456789abcdef",
        "0123456789ABCDEF",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ];

    /// <summary>The token lengths represented by the calibration corpus.</summary>
    private static readonly int[] s_lengths = [16, 20, 24, 32, 36, 40, 48, 64, 80, 96];

    /// <summary>The structured provider-style prefixes represented by the random class.</summary>
    private static readonly string[] s_prefixes =
    [
        "",
        "ghp_",
        "github_pat_",
        "sgp_",
        "sk_live_",
        "token-",
    ];

    /// <summary>The benign vocabulary used to generate the structured class.</summary>
    private static readonly string[] s_words =
    [
        "access",
        "account",
        "application",
        "configuration",
        "connection",
        "credential",
        "database",
        "development",
        "environment",
        "example",
        "internal",
        "localhost",
        "password",
        "placeholder",
        "production",
        "project",
        "sample",
        "scanner",
        "secret",
        "service",
        "staging",
        "storage",
        "token",
        "undefined",
    ];

    /// <summary>
    /// Creates balanced named samples with the runtime model feature vector.
    /// </summary>
    /// <param name="startIndex">The deterministic corpus start index.</param>
    /// <param name="samplesPerClass">The sample count for each class.</param>
    /// <returns>The named samples and runtime feature vectors.</returns>
    internal static List<(string Value, double[] Features, double Label)> CreateFeatureSamples(
        int startIndex,
        int samplesPerClass)
    {
        List<(string Value, double Label)> values = CreateValues(startIndex, samplesPerClass);
        var samples = new List<(string Value, double[] Features, double Label)>(values.Count);
        foreach ((string value, double label) in values)
        {
            samples.Add((value, CreateFeatureVector(value), label));
        }

        return samples;
    }

    /// <summary>
    /// Creates balanced values from independent deterministic random and structured generators.
    /// </summary>
    /// <param name="startIndex">The deterministic corpus start index.</param>
    /// <param name="samplesPerClass">The sample count for each class.</param>
    /// <returns>The sample values and class labels.</returns>
    internal static List<(string Value, double Label)> CreateValues(int startIndex, int samplesPerClass)
    {
        var values = new List<(string Value, double Label)>(samplesPerClass * 2);
        for (int i = 0; i < samplesPerClass; i++)
        {
            int corpusIndex = startIndex + i;
            values.Add((CreateRandomSample(corpusIndex), 1));
            values.Add((CreateStructuredSample(corpusIndex), 0));
        }

        return values;
    }

    /// <summary>
    /// Converts scorer features into the stable runtime model input order.
    /// </summary>
    /// <param name="value">The sample text.</param>
    /// <returns>The model input vector.</returns>
    internal static double[] CreateFeatureVector(string value)
    {
        SecretRandomnessFeatures features = SecretRandomnessScorer.ExtractFeatures(Encoding.UTF8.GetBytes(value));
        return
        [
            features.LengthScore,
            features.NormalizedEntropy,
            features.ExpectedDistinctRatio,
            features.TransitionDiversity,
            features.LongestRunRatio,
            features.SequentialPairRatio,
            features.RepeatedPatternRatio,
            features.CommonBigramRatio,
            features.CharacterClassBalance,
            features.EncodedTextSignal,
            features.PlaceholderSignal,
        ];
    }

    /// <summary>
    /// Creates a deterministic uniformly sampled token family member.
    /// </summary>
    /// <param name="index">The corpus index.</param>
    /// <returns>The random sample.</returns>
    private static string CreateRandomSample(int index)
    {
        string alphabet = s_alphabets[index % s_alphabets.Length];
        int length = s_lengths[(index / s_alphabets.Length) % s_lengths.Length];
        string prefix = s_prefixes[(index / (s_alphabets.Length * s_lengths.Length)) % s_prefixes.Length];
        var builder = new StringBuilder(prefix, prefix.Length + length);
        builder.Append(prefix);
        int generated = 0;
        int block = 0;
        int rejectionLimit = 256 - (256 % alphabet.Length);
        while (generated < length)
        {
            byte[] seed = Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"picket-random-v1:{index}:{block}"));
            byte[] digest = SHA256.HashData(seed);
            foreach (byte value in digest)
            {
                if (value >= rejectionLimit)
                {
                    continue;
                }

                builder.Append(alphabet[value % alphabet.Length]);
                generated++;
                if (generated == length)
                {
                    break;
                }
            }

            block++;
        }

        return builder.ToString();
    }

    /// <summary>
    /// Creates a deterministic structured or human-authored token family member.
    /// </summary>
    /// <param name="index">The corpus index.</param>
    /// <returns>The structured sample.</returns>
    private static string CreateStructuredSample(int index)
    {
        string first = s_words[index % s_words.Length];
        string second = s_words[(index * 7 + 5) % s_words.Length];
        string third = s_words[(index * 13 + 11) % s_words.Length];
        return (index % 10) switch
        {
            0 => string.Concat(first, second, third),
            1 => string.Create(CultureInfo.InvariantCulture, $"{first}_{second}_{2020 + (index % 20)}"),
            2 => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..(16 + (index % 20))],
            3 => new string((char)('A' + (index % 26)), 16 + (index % 48)),
            4 => string.Concat(first, index.ToString("D8", CultureInfo.InvariantCulture), first),
            5 => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Concat(first, "-", second, "-", third))),
            6 => string.Create(CultureInfo.InvariantCulture, $"v{1 + (index % 20)}.{index % 100}.{index % 1000}"),
            7 => string.Concat("abc123", "abc123", "abc123", index % 10),
            8 => string.Create(CultureInfo.InvariantCulture, $"{first}{2020 + (index % 20)}!{second}"),
            _ => string.Concat(first, "-", second, ".internal.local"),
        };
    }
}
