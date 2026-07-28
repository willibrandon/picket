using BenchmarkDotNet.Attributes;
using Microsoft.ML.Tokenizers;
using Picket.Engine;
using System.Text;

/// <summary>
/// Compares the current randomness scorer with Cl100k token-density and token-rank evaluation.
/// </summary>
[MemoryDiagnoser(displayGenColumns: false)]
public class BpeRandomnessBenchmarks
{
    /// <summary>The initialized Cl100k tokenizer excluded from measured setup time.</summary>
    private Tokenizer _tokenizer = null!;

    /// <summary>The deterministic representative token evaluated by each benchmark.</summary>
    private string _value = null!;

    /// <summary>
    /// Creates the deterministic benchmark input and initializes the tokenizer outside measurement.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        var random = new Random(42);
        var builder = new StringBuilder(48);
        for (int index = 0; index < builder.Capacity; index++)
        {
            builder.Append(Alphabet[random.Next(Alphabet.Length)]);
        }

        _value = builder.ToString();
        _tokenizer = TiktokenTokenizer.CreateForEncoding("cl100k_base");
    }

    /// <summary>
    /// Scores the candidate with the current native randomness model.
    /// </summary>
    /// <returns>The current model score.</returns>
    [Benchmark(Baseline = true)]
    public double ExistingRandomnessModel()
    {
        return SecretRandomnessScorer.Assess(_value).Score;
    }

    /// <summary>
    /// Scores the candidate and evaluates its Cl100k token density and mean token rank.
    /// </summary>
    /// <returns>A consumed value derived from both operations.</returns>
    [Benchmark]
    public double ExistingModelWithBpe()
    {
        IReadOnlyList<int> tokenIds = _tokenizer.EncodeToIds(_value);
        long tokenIdTotal = 0;
        foreach (int tokenId in tokenIds)
        {
            tokenIdTotal += tokenId;
        }

        return SecretRandomnessScorer.Assess(_value).Score
            + tokenIds.Count
            + (tokenIdTotal / (double)tokenIds.Count);
    }
}
