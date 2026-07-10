namespace Picket.Engine;

/// <summary>
/// Describes the non-secret statistical features used by the Picket randomness model.
/// </summary>
public sealed class SecretRandomnessFeatures
{
    /// <summary>
    /// Creates a feature vector from persisted non-secret metrics.
    /// </summary>
    /// <param name="sampleOffset">The zero-based sample byte offset.</param>
    /// <param name="sampleLength">The sampled byte count.</param>
    /// <param name="alphabet">The inferred alphabet name.</param>
    /// <param name="lengthScore">The normalized sample-length feature.</param>
    /// <param name="normalizedEntropy">The normalized entropy feature.</param>
    /// <param name="expectedDistinctRatio">The expected distinct-byte ratio.</param>
    /// <param name="transitionDiversity">The adjacent-transition diversity.</param>
    /// <param name="longestRunRatio">The longest-run ratio.</param>
    /// <param name="sequentialPairRatio">The sequential-pair ratio.</param>
    /// <param name="repeatedPatternRatio">The repeated-pattern ratio.</param>
    /// <param name="commonBigramRatio">The common-bigram ratio.</param>
    /// <param name="characterClassBalance">The character-class balance.</param>
    /// <param name="encodedTextSignal">The encoded printable-text signal.</param>
    /// <param name="placeholderSignal">The placeholder signal.</param>
    /// <returns>The feature vector.</returns>
    public static SecretRandomnessFeatures Create(
        int sampleOffset,
        int sampleLength,
        string alphabet,
        double lengthScore,
        double normalizedEntropy,
        double expectedDistinctRatio,
        double transitionDiversity,
        double longestRunRatio,
        double sequentialPairRatio,
        double repeatedPatternRatio,
        double commonBigramRatio,
        double characterClassBalance,
        double encodedTextSignal,
        double placeholderSignal)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sampleOffset);
        ArgumentOutOfRangeException.ThrowIfNegative(sampleLength);
        ArgumentException.ThrowIfNullOrWhiteSpace(alphabet);
        ValidateProbability(lengthScore, nameof(lengthScore));
        ValidateProbability(normalizedEntropy, nameof(normalizedEntropy));
        ValidateProbability(expectedDistinctRatio, nameof(expectedDistinctRatio));
        ValidateProbability(transitionDiversity, nameof(transitionDiversity));
        ValidateProbability(longestRunRatio, nameof(longestRunRatio));
        ValidateProbability(sequentialPairRatio, nameof(sequentialPairRatio));
        ValidateProbability(repeatedPatternRatio, nameof(repeatedPatternRatio));
        ValidateProbability(commonBigramRatio, nameof(commonBigramRatio));
        ValidateProbability(characterClassBalance, nameof(characterClassBalance));
        ValidateProbability(encodedTextSignal, nameof(encodedTextSignal));
        ValidateProbability(placeholderSignal, nameof(placeholderSignal));
        return new SecretRandomnessFeatures(
            sampleOffset,
            sampleLength,
            alphabet,
            lengthScore,
            normalizedEntropy,
            expectedDistinctRatio,
            transitionDiversity,
            longestRunRatio,
            sequentialPairRatio,
            repeatedPatternRatio,
            commonBigramRatio,
            characterClassBalance,
            encodedTextSignal,
            placeholderSignal);
    }

    internal SecretRandomnessFeatures(
        int sampleOffset,
        int sampleLength,
        string alphabet,
        double lengthScore,
        double normalizedEntropy,
        double expectedDistinctRatio,
        double transitionDiversity,
        double longestRunRatio,
        double sequentialPairRatio,
        double repeatedPatternRatio,
        double commonBigramRatio,
        double characterClassBalance,
        double encodedTextSignal,
        double placeholderSignal)
    {
        SampleOffset = sampleOffset;
        SampleLength = sampleLength;
        Alphabet = alphabet;
        LengthScore = lengthScore;
        NormalizedEntropy = normalizedEntropy;
        ExpectedDistinctRatio = expectedDistinctRatio;
        TransitionDiversity = transitionDiversity;
        LongestRunRatio = longestRunRatio;
        SequentialPairRatio = sequentialPairRatio;
        RepeatedPatternRatio = repeatedPatternRatio;
        CommonBigramRatio = commonBigramRatio;
        CharacterClassBalance = characterClassBalance;
        EncodedTextSignal = encodedTextSignal;
        PlaceholderSignal = placeholderSignal;
    }

    /// <summary>
    /// Gets the zero-based byte offset of the token-like sample within the secret.
    /// </summary>
    public int SampleOffset { get; }

    /// <summary>
    /// Gets the sampled byte count.
    /// </summary>
    public int SampleLength { get; }

    /// <summary>
    /// Gets the inferred alphabet name.
    /// </summary>
    public string Alphabet { get; }

    /// <summary>
    /// Gets the logarithmically normalized sample-length feature.
    /// </summary>
    public double LengthScore { get; }

    /// <summary>
    /// Gets the Shannon entropy normalized for the inferred alphabet and sample length.
    /// </summary>
    public double NormalizedEntropy { get; }

    /// <summary>
    /// Gets the observed distinct-byte count divided by its expectation under a uniform source.
    /// </summary>
    public double ExpectedDistinctRatio { get; }

    /// <summary>
    /// Gets the ratio of distinct adjacent byte pairs.
    /// </summary>
    public double TransitionDiversity { get; }

    /// <summary>
    /// Gets the longest identical-byte run divided by the sample length.
    /// </summary>
    public double LongestRunRatio { get; }

    /// <summary>
    /// Gets the ratio of adjacent ASCII letter or digit pairs that form ascending or descending sequences.
    /// </summary>
    public double SequentialPairRatio { get; }

    /// <summary>
    /// Gets the strongest short-period repetition ratio.
    /// </summary>
    public double RepeatedPatternRatio { get; }

    /// <summary>
    /// Gets the ratio of adjacent ASCII pairs that are common in source identifiers and English text.
    /// </summary>
    public double CommonBigramRatio { get; }

    /// <summary>
    /// Gets the observed character-class balance relative to the inferred uniform alphabet.
    /// </summary>
    public double CharacterClassBalance { get; }

    /// <summary>
    /// Gets the bounded signal that the sample is Base64-encoded printable text.
    /// </summary>
    public double EncodedTextSignal { get; }

    /// <summary>
    /// Gets a value indicating whether the sample contains a known placeholder marker.
    /// </summary>
    public double PlaceholderSignal { get; }

    private static void ValidateProbability(double value, string parameterName)
    {
        if (!double.IsFinite(value) || value < 0 || value > 1)
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Value must be finite and between zero and one.");
        }
    }
}
