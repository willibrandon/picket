namespace Picket.Analyze;

/// <summary>
/// Supplies non-secret provider metadata for credential analysis.
/// </summary>
/// <param name="identity">The discovered credential identity, or an empty string.</param>
/// <param name="scopes">The discovered credential scopes.</param>
/// <param name="reachableResources">The discovered reachable resources.</param>
/// <param name="evidence">Non-secret evidence collected during provider analysis.</param>
public sealed class CredentialAnalysisMetadata(
    string identity = "",
    string[]? scopes = null,
    string[]? reachableResources = null,
    string[]? evidence = null)
{
    /// <summary>
    /// Gets the discovered credential identity, or an empty string.
    /// </summary>
    public string Identity { get; } = identity ?? string.Empty;

    /// <summary>
    /// Gets the discovered credential scopes.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; } = CopyOrEmpty(scopes);

    /// <summary>
    /// Gets the discovered reachable resources.
    /// </summary>
    public IReadOnlyList<string> ReachableResources { get; } = CopyOrEmpty(reachableResources);

    /// <summary>
    /// Gets non-secret evidence collected during provider analysis.
    /// </summary>
    public IReadOnlyList<string> Evidence { get; } = CopyOrEmpty(evidence);

    private static string[] CopyOrEmpty(string[]? values)
    {
        if (values is null || values.Length == 0)
        {
            return [];
        }

        var copy = new string[values.Length];
        Array.Copy(values, copy, values.Length);
        return copy;
    }
}
