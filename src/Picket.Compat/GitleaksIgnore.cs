using Picket.Engine;

namespace Picket.Compat;

/// <summary>
/// Represents Gitleaks-compatible fingerprint ignore entries.
/// </summary>
/// <param name="fingerprints">Fingerprint entries to store exactly.</param>
public sealed class GitleaksIgnore(IEnumerable<string> fingerprints)
{
    private readonly HashSet<string> _fingerprints = CreateFingerprintSet(fingerprints);

    /// <summary>
    /// Gets an empty ignore set.
    /// </summary>
    public static GitleaksIgnore Empty { get; } = new([]);

    /// <summary>
    /// Gets the number of loaded fingerprint entries.
    /// </summary>
    public int Count => _fingerprints.Count;

    /// <summary>
    /// Loads ignore entries from a .gitleaksignore file.
    /// </summary>
    /// <param name="path">The file path to load.</param>
    /// <returns>The loaded ignore set.</returns>
    public static GitleaksIgnore Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromLines(File.ReadLines(path));
    }

    /// <summary>
    /// Loads ignore entries from every existing file path in order.
    /// </summary>
    /// <param name="paths">Candidate .gitleaksignore file paths.</param>
    /// <returns>The loaded ignore set.</returns>
    public static GitleaksIgnore LoadExisting(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (string path in paths)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            foreach (string line in File.ReadLines(path))
            {
                AddLine(fingerprints, line);
            }
        }

        return fingerprints.Count == 0 ? Empty : new GitleaksIgnore(fingerprints);
    }

    /// <summary>
    /// Parses ignore entries from lines using Gitleaks-compatible rules.
    /// </summary>
    /// <param name="lines">The lines to parse.</param>
    /// <returns>The parsed ignore set.</returns>
    public static GitleaksIgnore FromLines(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in lines)
        {
            AddLine(fingerprints, line);
        }

        return fingerprints.Count == 0 ? Empty : new GitleaksIgnore(fingerprints);
    }

    /// <summary>
    /// Returns findings not suppressed by this ignore set.
    /// </summary>
    /// <param name="findings">Findings to filter.</param>
    /// <returns>The non-ignored findings in input order.</returns>
    public IReadOnlyList<Finding> Filter(IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (_fingerprints.Count == 0 || findings.Count == 0)
        {
            return findings;
        }

        var filtered = new List<Finding>(findings.Count);
        foreach (Finding finding in findings)
        {
            if (!IsIgnored(finding))
            {
                filtered.Add(finding);
            }
        }

        return filtered;
    }

    /// <summary>
    /// Returns a value indicating whether a finding is suppressed.
    /// </summary>
    /// <param name="finding">The finding to test.</param>
    /// <returns><see langword="true" /> when the finding is ignored.</returns>
    public bool IsIgnored(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        string globalFingerprint = CreateGlobalFingerprint(finding);
        if (_fingerprints.Contains(globalFingerprint))
        {
            return true;
        }

        return finding.Commit.Length != 0 && _fingerprints.Contains(finding.Fingerprint);
    }

    private static void AddLine(HashSet<string> fingerprints, string line)
    {
        string trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed.StartsWith('#'))
        {
            return;
        }

        fingerprints.Add(NormalizeFingerprint(trimmed));
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        string[] parts = fingerprint.Split(':');
        switch (parts.Length)
        {
            case 3:
                parts[0] = NormalizePath(parts[0]);
                break;
            case 4:
                parts[1] = NormalizePath(parts[1]);
                break;
        }

        return string.Join(':', parts);
    }

    private static string CreateGlobalFingerprint(Finding finding)
    {
        return $"{NormalizePath(finding.File)}:{finding.RuleID}:{finding.StartLine}";
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    private static HashSet<string> CreateFingerprintSet(IEnumerable<string> fingerprints)
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        return new HashSet<string>(fingerprints, StringComparer.Ordinal);
    }
}
