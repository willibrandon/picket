/// <summary>
/// Fits and evaluates the deterministic logistic model used by randomness experiments.
/// </summary>
internal static class RandomnessLogisticModel
{
    /// <summary>The deterministic batch-gradient iteration count.</summary>
    private const int TrainingIterations = 12000;

    /// <summary>The fixed batch-gradient learning rate.</summary>
    private const double LearningRate = 0.35;

    /// <summary>The L2 regularization coefficient.</summary>
    private const double L2Penalty = 0.0025;

    /// <summary>
    /// Fits a regularized logistic model with deterministic batch gradient descent.
    /// </summary>
    /// <param name="samples">The balanced training samples.</param>
    /// <returns>The fitted intercept and feature weights.</returns>
    internal static double[] Train(List<(double[] Features, double Label)> samples)
    {
        var weights = new double[samples[0].Features.Length + 1];
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
                weights[weightIndex] -= scale
                    * (gradients[weightIndex] + (L2Penalty * samples.Count * weights[weightIndex]));
            }
        }

        return weights;
    }

    /// <summary>
    /// Evaluates the logistic model for one feature vector.
    /// </summary>
    /// <param name="weights">The intercept and feature weights.</param>
    /// <param name="features">The feature vector.</param>
    /// <returns>The unquantized score.</returns>
    internal static double Predict(double[] weights, double[] features)
    {
        double linearScore = weights[0];
        for (int i = 0; i < features.Length; i++)
        {
            linearScore += weights[i + 1] * features[i];
        }

        return 1 / (1 + Math.Exp(-linearScore));
    }
}
