#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:project ../src/Picket.Engine/Picket.Engine.csproj
#:include RandomnessCalibrationCorpus.cs
#:include RandomnessLogisticModel.cs

using Picket.Engine;
using System.Globalization;

return RandomnessModelCalibrationApp.Run(args);

/// <summary>
/// Reproduces the deterministic training and holdout calibration for the native randomness model.
/// </summary>
internal static class RandomnessModelCalibrationApp
{
    /// <summary>The number of independent holdout samples generated for each class.</summary>
    private const int HoldoutSamplesPerClass = 256;

    /// <summary>The number of training samples generated for each class.</summary>
    private const int TrainingSamplesPerClass = 1024;

    /// <summary>The maximum accepted score difference from checked-in coefficients.</summary>
    private const double MaximumVerificationDelta = 0.000002;

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

        List<(string Value, double[] Features, double Label)> namedTrainingSamples =
            RandomnessCalibrationCorpus.CreateFeatureSamples(0, TrainingSamplesPerClass);
        var trainingSamples = new List<(double[] Features, double Label)>(namedTrainingSamples.Count);
        foreach ((_, double[] features, double label) in namedTrainingSamples)
        {
            trainingSamples.Add((features, label));
        }

        double[] weights = RandomnessLogisticModel.Train(trainingSamples);
        List<(string Value, double[] Features, double Label)> holdoutSamples =
            RandomnessCalibrationCorpus.CreateFeatureSamples(100_000, HoldoutSamplesPerClass);
        WriteMetrics(weights, holdoutSamples);
        WriteCoefficients(weights);

        if (!verify)
        {
            return 0;
        }

        double maximumDelta = 0;
        foreach ((string value, double[] features, _) in holdoutSamples)
        {
            double fittedScore = Quantize(RandomnessLogisticModel.Predict(weights, features));
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
            double score = RandomnessLogisticModel.Predict(weights, features);
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
