using Picket.Engine;
using Picket.Sources;

namespace Picket;

internal static partial class Program
{
    private const string GitCombinedProvenance = "git-index+worktree";
    private const string GitIndexProvenance = "git-index";
    private const string GitWorktreeProvenance = "git-worktree";

    static IReadOnlyList<Finding> ApplySourceProvenance(
        IReadOnlyList<Finding> findings,
        SourceFile sourceFile)
    {
        if (findings.Count == 0 || sourceFile.ProvenanceType.Length == 0)
        {
            return findings;
        }

        var annotated = new List<Finding>(findings.Count);
        for (int index = 0; index < findings.Count; index++)
        {
            annotated.Add(findings[index].WithProvenanceType(sourceFile.ProvenanceType));
        }

        return annotated;
    }

    static List<Finding> MergeGitChangeFindings(List<Finding> findings)
    {
        var merged = new List<Finding>(findings.Count);
        var indexOccurrences = new Dictionary<string, Queue<int>>(StringComparer.Ordinal);
        for (int findingIndex = 0; findingIndex < findings.Count; findingIndex++)
        {
            Finding finding = findings[findingIndex];
            string fingerprint = StableFindingFingerprint.Create(finding);
            if (finding.ProvenanceType.Equals(GitIndexProvenance, StringComparison.Ordinal))
            {
                int resultIndex = merged.Count;
                merged.Add(finding);
                if (!indexOccurrences.TryGetValue(fingerprint, out Queue<int>? occurrences))
                {
                    occurrences = new Queue<int>();
                    indexOccurrences.Add(fingerprint, occurrences);
                }

                occurrences.Enqueue(resultIndex);
                continue;
            }

            if (finding.ProvenanceType.Equals(GitWorktreeProvenance, StringComparison.Ordinal)
                && indexOccurrences.TryGetValue(fingerprint, out Queue<int>? indexMatches)
                && indexMatches.Count != 0)
            {
                merged[indexMatches.Dequeue()] = finding.WithProvenanceType(GitCombinedProvenance);
                continue;
            }

            merged.Add(finding);
        }

        return merged;
    }
}
