namespace Picket.Engine;

/// <summary>
/// Represents a deterministic estimate that secret material resembles a uniformly generated token.
/// </summary>
public sealed class SecretRandomnessAssessment
{
    /// <summary>
    /// Creates an assessment from persisted non-secret model output.
    /// </summary>
    /// <param name="model">The stable model identifier.</param>
    /// <param name="score">The deterministic model score.</param>
    /// <param name="classification">The threshold-derived classification.</param>
    /// <param name="features">The model feature vector.</param>
    /// <param name="signals">The stable explanatory signal identifiers.</param>
    /// <returns>The assessment.</returns>
    public static SecretRandomnessAssessment Create(
        string model,
        double score,
        string classification,
        SecretRandomnessFeatures features,
        IReadOnlyList<string> signals)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        if (!double.IsFinite(score) || score < 0 || score > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(score), score, "Value must be finite and between zero and one.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(classification);
        ArgumentNullException.ThrowIfNull(features);
        ArgumentNullException.ThrowIfNull(signals);
        return new SecretRandomnessAssessment(model, score, classification, features, signals);
    }

    internal SecretRandomnessAssessment(
        string model,
        double score,
        string classification,
        SecretRandomnessFeatures features,
        IReadOnlyList<string> signals)
    {
        Model = model;
        Score = score;
        Classification = classification;
        Features = features;
        Signals = signals;
    }

    /// <summary>
    /// Gets the stable model identifier.
    /// </summary>
    public string Model { get; }

    /// <summary>
    /// Gets the deterministic model score from zero through one.
    /// </summary>
    public double Score { get; }

    /// <summary>
    /// Gets the threshold-derived classification.
    /// </summary>
    public string Classification { get; }

    /// <summary>
    /// Gets the non-secret statistical features used by the model.
    /// </summary>
    public SecretRandomnessFeatures Features { get; }

    /// <summary>
    /// Gets the stable signal identifiers that explain material score contributions.
    /// </summary>
    public IReadOnlyList<string> Signals { get; }
}
