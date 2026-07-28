#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:property ManagePackageVersionsCentrally=false
#:package Microsoft.Bcl.Memory@10.0.10
#:package Microsoft.ML.Tokenizers.Data.Cl100kBase@2.0.0
#:project ../src/Picket.Engine/Picket.Engine.csproj
#:include RandomnessCalibrationCorpus.cs
#:include RandomnessLogisticModel.cs

using Microsoft.ML.Tokenizers;
using Picket.Engine;
using System.Globalization;
using System.Text;

return BpeRandomnessEvaluationApp.Run(args);

/// <summary>
/// Compares Cl100k token density and token rank with Picket's native randomness model.
/// </summary>
internal static class BpeRandomnessEvaluationApp
{
    /// <summary>The number of independent holdout samples generated for each class.</summary>
    private const int HoldoutSamplesPerClass = 256;

    /// <summary>The number of training samples generated for each class.</summary>
    private const int TrainingSamplesPerClass = 1024;

    /// <summary>The minimum absolute recall improvement considered meaningful.</summary>
    private const double MinimumRecallImprovement = 0.01;

    /// <summary>The Cl100k mergeable-token vocabulary size used to normalize token identifiers.</summary>
    private const double TokenVocabularySize = 100_256;

    /// <summary>The accepted deterministic metric drift in verification mode.</summary>
    private const double VerificationTolerance = 0.0000005;

    /// <summary>
    /// Runs the deterministic baseline and BPE candidate evaluation.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        bool verify = args.Length == 1 && args[0].Equals("--verify", StringComparison.Ordinal);
        if (args.Length != 0 && !verify)
        {
            Console.Error.WriteLine("usage: dotnet run --file scripts/Evaluate-BpeRandomness.cs -- [--verify]");
            return 2;
        }

        Tokenizer tokenizer = TiktokenTokenizer.CreateForEncoding("cl100k_base");
        List<(string Value, double Label)> trainingValues =
            RandomnessCalibrationCorpus.CreateValues(0, TrainingSamplesPerClass);
        List<(string Value, double Label)> holdoutValues =
            RandomnessCalibrationCorpus.CreateValues(100_000, HoldoutSamplesPerClass);
        double[] baselineWeights = RandomnessLogisticModel.Train(CreateFeatureSamples(trainingValues, tokenizer: null));
        double[] candidateWeights = RandomnessLogisticModel.Train(CreateFeatureSamples(trainingValues, tokenizer));
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall)
            baseline = Evaluate(baselineWeights, holdoutValues, tokenizer: null);
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall)
            candidate = Evaluate(candidateWeights, holdoutValues, tokenizer);

        WriteMetrics("baseline", baseline);
        WriteMetrics("candidate", candidate);
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"candidate token-density weight: {candidateWeights[^2]:F9}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"candidate mean-token-rank weight: {candidateWeights[^1]:F9}"));

        bool accepted = IsAccepted(baseline, candidate);
        Console.Out.WriteLine(accepted ? "decision: accept" : "decision: reject");
        if (!accepted)
        {
            Console.Out.WriteLine(
                "reason: no meaningful holdout recall lift without an accuracy, precision, or recall regression");
        }

        if (!verify)
        {
            return 0;
        }

        bool metricsMatch = MatchesExpectedMetrics(baseline, candidate);
        if (!metricsMatch || accepted)
        {
            Console.Error.WriteLine("BPE randomness evaluation no longer matches the reviewed decision");
            return 1;
        }

        return 0;
    }

    /// <summary>
    /// Creates fitted feature samples with or without BPE evidence.
    /// </summary>
    /// <param name="values">The deterministic corpus values.</param>
    /// <param name="tokenizer">The tokenizer, or <see langword="null"/> for the baseline.</param>
    /// <returns>The feature samples.</returns>
    private static List<(double[] Features, double Label)> CreateFeatureSamples(
        List<(string Value, double Label)> values,
        Tokenizer? tokenizer)
    {
        var samples = new List<(double[] Features, double Label)>(values.Count);
        foreach ((string value, double label) in values)
        {
            samples.Add((CreateFeatureVector(value, tokenizer), label));
        }

        return samples;
    }

    /// <summary>
    /// Creates the runtime feature vector with optional normalized BPE evidence.
    /// </summary>
    /// <param name="value">The corpus value.</param>
    /// <param name="tokenizer">The tokenizer, or <see langword="null"/> for the baseline.</param>
    /// <returns>The model feature vector.</returns>
    private static double[] CreateFeatureVector(string value, Tokenizer? tokenizer)
    {
        double[] baseline = RandomnessCalibrationCorpus.CreateFeatureVector(value);
        if (tokenizer is null)
        {
            return baseline;
        }

        IReadOnlyList<int> tokenIds = tokenizer.EncodeToIds(value);
        int tokenCount = tokenIds.Count;
        long tokenIdTotal = 0;
        foreach (int tokenId in tokenIds)
        {
            tokenIdTotal += tokenId;
        }

        var candidate = new double[baseline.Length + 2];
        baseline.CopyTo(candidate, 0);
        candidate[^2] = tokenCount == 0
            ? 0
            : Math.Clamp(tokenCount / (double)Math.Max(1, Encoding.UTF8.GetByteCount(value)), 0, 1);
        candidate[^1] = tokenCount == 0
            ? 0
            : tokenIdTotal / (double)tokenCount / TokenVocabularySize;
        return candidate;
    }

    /// <summary>
    /// Evaluates holdout discrimination and calibration metrics.
    /// </summary>
    /// <param name="weights">The fitted model weights.</param>
    /// <param name="values">The independent holdout values.</param>
    /// <param name="tokenizer">The tokenizer, or <see langword="null"/> for the baseline.</param>
    /// <returns>The evaluated metrics.</returns>
    private static (
        double Accuracy,
        double Brier,
        double RandomPrecision,
        double RandomRecall,
        double StructuredRecall) Evaluate(
        double[] weights,
        List<(string Value, double Label)> values,
        Tokenizer? tokenizer)
    {
        int correct = 0;
        int randomCount = 0;
        int randomPredicted = 0;
        int randomTruePositive = 0;
        int structuredCount = 0;
        int structuredTrueNegative = 0;
        double brier = 0;
        foreach ((string value, double label) in values)
        {
            double score = RandomnessLogisticModel.Predict(weights, CreateFeatureVector(value, tokenizer));
            double error = score - label;
            brier += error * error;
            if ((score >= 0.5) == (label == 1))
            {
                correct++;
            }

            if (score >= SecretRandomnessScorer.LikelyRandomThreshold)
            {
                randomPredicted++;
                if (label == 1)
                {
                    randomTruePositive++;
                }
            }

            if (label == 1)
            {
                randomCount++;
            }
            else
            {
                structuredCount++;
                if (score <= SecretRandomnessScorer.LikelyStructuredThreshold)
                {
                    structuredTrueNegative++;
                }
            }
        }

        return (
            correct / (double)values.Count,
            brier / values.Count,
            randomTruePositive / (double)Math.Max(1, randomPredicted),
            randomTruePositive / (double)randomCount,
            structuredTrueNegative / (double)structuredCount);
    }

    /// <summary>
    /// Determines whether the candidate provides meaningful lift without a discrimination regression.
    /// </summary>
    /// <param name="baseline">The baseline metrics.</param>
    /// <param name="candidate">The candidate metrics.</param>
    /// <returns><see langword="true"/> when the candidate meets the quality gate.</returns>
    private static bool IsAccepted(
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall) baseline,
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall) candidate)
    {
        bool recallLift = candidate.RandomRecall >= baseline.RandomRecall + MinimumRecallImprovement
            || candidate.StructuredRecall >= baseline.StructuredRecall + MinimumRecallImprovement;
        return recallLift
            && candidate.Accuracy >= baseline.Accuracy
            && candidate.RandomPrecision >= baseline.RandomPrecision
            && candidate.RandomRecall >= baseline.RandomRecall
            && candidate.StructuredRecall >= baseline.StructuredRecall;
    }

    /// <summary>
    /// Writes one deterministic metric set.
    /// </summary>
    /// <param name="name">The metric-set name.</param>
    /// <param name="metrics">The evaluated metrics.</param>
    private static void WriteMetrics(
        string name,
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall) metrics)
    {
        Console.Out.WriteLine(name);
        Console.Out.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  accuracy: {metrics.Accuracy:F6}"));
        Console.Out.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  brier score: {metrics.Brier:F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  likely-random precision: {metrics.RandomPrecision:F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  likely-random recall: {metrics.RandomRecall:F6}"));
        Console.Out.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  likely-structured recall: {metrics.StructuredRecall:F6}"));
    }

    /// <summary>
    /// Verifies the deterministic metric values reviewed for this evaluation.
    /// </summary>
    /// <param name="baseline">The baseline metrics.</param>
    /// <param name="candidate">The candidate metrics.</param>
    /// <returns><see langword="true"/> when every metric matches.</returns>
    private static bool MatchesExpectedMetrics(
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall) baseline,
        (double Accuracy, double Brier, double RandomPrecision, double RandomRecall, double StructuredRecall) candidate)
    {
        return IsClose(baseline.Accuracy, 0.998047)
            && IsClose(baseline.Brier, 0.014483)
            && IsClose(baseline.RandomPrecision, 1)
            && IsClose(baseline.RandomRecall, 0.9375)
            && IsClose(baseline.StructuredRecall, 0.90625)
            && IsClose(candidate.Accuracy, 0.998047)
            && IsClose(candidate.Brier, 0.014087)
            && IsClose(candidate.RandomPrecision, 1)
            && IsClose(candidate.RandomRecall, 0.9375)
            && IsClose(candidate.StructuredRecall, 0.875);
    }

    /// <summary>
    /// Compares a metric with its reviewed deterministic value.
    /// </summary>
    /// <param name="actual">The actual metric.</param>
    /// <param name="expected">The expected metric.</param>
    /// <returns><see langword="true"/> when the values are within tolerance.</returns>
    private static bool IsClose(double actual, double expected)
    {
        return Math.Abs(actual - expected) <= VerificationTolerance;
    }
}
