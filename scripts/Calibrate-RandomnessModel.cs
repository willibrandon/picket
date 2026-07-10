#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:project ../src/Picket.Engine/Picket.Engine.csproj

using Picket.Engine;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

return RandomnessModelCalibrationApp.Run(args);

/// <summary>
/// Reproduces the deterministic training and holdout calibration for the native randomness model.
/// </summary>
internal static class RandomnessModelCalibrationApp
{
    /// <summary>The number of fitted model features.</summary>
    private const int FeatureCount = 11;

    /// <summary>The number of independent holdout samples generated for each class.</summary>
    private const int HoldoutSamplesPerClass = 256;

    /// <summary>The deterministic batch-gradient iteration count.</summary>
    private const int TrainingIterations = 12000;

    /// <summary>The number of training samples generated for each class.</summary>
    private const int TrainingSamplesPerClass = 1024;

    /// <summary>The fixed batch-gradient learning rate.</summary>
    private const double LearningRate = 0.35;

    /// <summary>The L2 regularization coefficient.</summary>
    private const double L2Penalty = 0.0025;

    /// <summary>The maximum accepted score difference from checked-in coefficients.</summary>
    private const double MaximumVerificationDelta = 0.000002;

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
    /// Runs model fitting, holdout evaluation, and optional checked-in coefficient verification.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        bool verify = args.Length == 1 && args[0].Equals("--verify", StringComparison.Ordinal);
        if (args.Length != 0 && !verify)
        {
            Console.Error.WriteLine("usage: dotnet run --file scripts/Calibrate-RandomnessModel.cs -- [--verify]");
            return 2;
        }

        List<(double[] Features, double Label)> trainingSamples = CreateSamples(0, TrainingSamplesPerClass);
        double[] weights = Train(trainingSamples);
        List<(string Value, double[] Features, double Label)> holdoutSamples = CreateNamedSamples(100_000, HoldoutSamplesPerClass);
        WriteMetrics(weights, holdoutSamples);
        WriteCoefficients(weights);

        if (!verify)
        {
            return 0;
        }

        double maximumDelta = 0;
        foreach ((string value, double[] features, _) in holdoutSamples)
        {
            double fittedScore = Quantize(Predict(weights, features));
            double checkedInScore = SecretRandomnessScorer.Assess(value).Score;
            maximumDelta = Math.Max(maximumDelta, Math.Abs(fittedScore - checkedInScore));
        }

        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"maximum checked-in score delta: {maximumDelta:F6}"));
        if (maximumDelta > MaximumVerificationDelta)
        {
            Console.Error.WriteLine("checked-in randomness coefficients do not match the reproducible calibration");
            return 1;
        }

        return 0;
    }

    /// <summary>
    /// Creates balanced anonymous training samples.
    /// </summary>
    /// <param name="startIndex">The deterministic corpus start index.</param>
    /// <param name="samplesPerClass">The sample count for each class.</param>
    /// <returns>The training samples.</returns>
    private static List<(double[] Features, double Label)> CreateSamples(int startIndex, int samplesPerClass)
    {
        List<(string Value, double[] Features, double Label)> namedSamples = CreateNamedSamples(startIndex, samplesPerClass);
        var samples = new List<(double[] Features, double Label)>(namedSamples.Count);
        foreach ((_, double[] features, double label) in namedSamples)
        {
            samples.Add((features, label));
        }

        return samples;
    }

    /// <summary>
    /// Creates balanced named samples from independent deterministic random and structured generators.
    /// </summary>
    /// <param name="startIndex">The deterministic corpus start index.</param>
    /// <param name="samplesPerClass">The sample count for each class.</param>
    /// <returns>The named samples.</returns>
    private static List<(string Value, double[] Features, double Label)> CreateNamedSamples(int startIndex, int samplesPerClass)
    {
        var samples = new List<(string Value, double[] Features, double Label)>(samplesPerClass * 2);
        for (int i = 0; i < samplesPerClass; i++)
        {
            int corpusIndex = startIndex + i;
            string random = CreateRandomSample(corpusIndex);
            string structured = CreateStructuredSample(corpusIndex);
            samples.Add((random, CreateFeatureVector(random), 1));
            samples.Add((structured, CreateFeatureVector(structured), 0));
        }

        return samples;
    }

    /// <summary>
    /// Fits a regularized logistic model with deterministic batch gradient descent.
    /// </summary>
    /// <param name="samples">The balanced training samples.</param>
    /// <returns>The fitted intercept and feature weights.</returns>
    private static double[] Train(List<(double[] Features, double Label)> samples)
    {
        var weights = new double[FeatureCount + 1];
        var gradients = new double[weights.Length];
        for (int iteration = 0; iteration < TrainingIterations; iteration++)
        {
            Array.Clear(gradients);
            foreach ((double[] features, double label) in samples)
            {
                double error = Predict(weights, features) - label;
                gradients[0] += error;
                for (int featureIndex = 0; featureIndex < features.Length; featureIndex++)
                {
                    gradients[featureIndex + 1] += error * features[featureIndex];
                }
            }

            double scale = LearningRate / samples.Count;
            weights[0] -= scale * gradients[0];
            for (int weightIndex = 1; weightIndex < weights.Length; weightIndex++)
            {
                weights[weightIndex] -= scale * (gradients[weightIndex] + (L2Penalty * samples.Count * weights[weightIndex]));
            }
        }

        return weights;
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

    /// <summary>
    /// Converts scorer features into the stable model input order.
    /// </summary>
    /// <param name="value">The sample text.</param>
    /// <returns>The model input vector.</returns>
    private static double[] CreateFeatureVector(string value)
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
    /// Evaluates the logistic model for one feature vector.
    /// </summary>
    /// <param name="weights">The intercept and feature weights.</param>
    /// <param name="features">The feature vector.</param>
    /// <returns>The unquantized score.</returns>
    private static double Predict(double[] weights, double[] features)
    {
        double linearScore = weights[0];
        for (int i = 0; i < features.Length; i++)
        {
            linearScore += weights[i + 1] * features[i];
        }

        return 1 / (1 + Math.Exp(-linearScore));
    }

    /// <summary>
    /// Writes holdout discrimination and calibration metrics.
    /// </summary>
    /// <param name="weights">The fitted model weights.</param>
    /// <param name="samples">The holdout samples.</param>
    private static void WriteMetrics(double[] weights, List<(string Value, double[] Features, double Label)> samples)
    {
        int correct = 0;
        int likelyRandomTruePositive = 0;
        int likelyRandomPredicted = 0;
        int likelyStructuredTrueNegative = 0;
        int randomCount = 0;
        int structuredCount = 0;
        double brier = 0;
        foreach ((_, double[] features, double label) in samples)
        {
            double score = Predict(weights, features);
            double error = score - label;
            brier += error * error;
            if ((score >= 0.5) == (label == 1))
            {
                correct++;
            }

            if (label == 1)
            {
                randomCount++;
                if (score >= SecretRandomnessScorer.LikelyRandomThreshold)
                {
                    likelyRandomTruePositive++;
                }
            }

            if (score >= SecretRandomnessScorer.LikelyRandomThreshold)
            {
                likelyRandomPredicted++;
            }

            if (label == 0)
            {
                structuredCount++;
                if (score <= SecretRandomnessScorer.LikelyStructuredThreshold)
                {
                    likelyStructuredTrueNegative++;
                }
            }
        }

        Console.Out.WriteLine(string.Create(CultureInfo.InvariantCulture, $"holdout samples: {samples.Count}"));
        Console.Out.WriteLine(string.Create(CultureInfo.InvariantCulture, $"accuracy: {correct / (double)samples.Count:F6}"));
        Console.Out.WriteLine(string.Create(CultureInfo.InvariantCulture, $"brier score: {brier / samples.Count:F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"likely-random precision: {likelyRandomTruePositive / (double)Math.Max(1, likelyRandomPredicted):F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"likely-random recall: {likelyRandomTruePositive / (double)randomCount:F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"likely-structured recall: {likelyStructuredTrueNegative / (double)structuredCount:F6}"));
    }

    /// <summary>
    /// Writes fitted coefficients in runtime source order.
    /// </summary>
    /// <param name="weights">The fitted model weights.</param>
    private static void WriteCoefficients(double[] weights)
    {
        string[] names =
        [
            "Intercept",
            "LengthWeight",
            "NormalizedEntropyWeight",
            "ExpectedDistinctWeight",
            "TransitionDiversityWeight",
            "LongestRunWeight",
            "SequentialPairWeight",
            "RepeatedPatternWeight",
            "CommonBigramWeight",
            "CharacterClassBalanceWeight",
            "EncodedTextWeight",
            "PlaceholderWeight",
        ];
        for (int i = 0; i < weights.Length; i++)
        {
            Console.Out.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"private const double {names[i]} = {weights[i]:G17};"));
        }
    }

    /// <summary>
    /// Quantizes a score using the runtime report contract.
    /// </summary>
    /// <param name="value">The score to quantize.</param>
    /// <returns>The quantized score.</returns>
    private static double Quantize(double value)
    {
        return Math.Round(value, 6, MidpointRounding.AwayFromZero);
    }
}
