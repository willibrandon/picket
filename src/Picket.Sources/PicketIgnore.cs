using System.Globalization;
using System.Security.Cryptography;

namespace Picket.Sources;

/// <summary>
/// Represents Picket-native ignore metadata loaded from .picketignore files.
/// </summary>
/// <param name="contentSha256Hashes">SHA-256 content hashes to suppress.</param>
public sealed class PicketIgnore(IEnumerable<string> contentSha256Hashes)
{
    private const string Sha256Prefix = "sha256:";
    private const int Sha256HexLength = 64;
    private readonly HashSet<string> _contentSha256Hashes = CreateHashSet(contentSha256Hashes);
    private readonly Dictionary<string, string> _contentSha256Locations = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _matchedContentSha256Hashes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets an empty native ignore set.
    /// </summary>
    public static PicketIgnore Empty { get; } = new([]);

    /// <summary>
    /// Gets the number of content-hash ignore entries.
    /// </summary>
    public int ContentHashCount => _contentSha256Hashes.Count;

    private PicketIgnore(HashSet<string> contentSha256Hashes, Dictionary<string, string> contentSha256Locations)
        : this(contentSha256Hashes)
    {
        _contentSha256Locations = contentSha256Locations;
    }

    /// <summary>
    /// Loads native ignore metadata from the root <c>.picketignore</c> file and explicit ignore files.
    /// </summary>
    /// <param name="root">The scan root.</param>
    /// <param name="ignoreFilePaths">Explicit ignore file paths.</param>
    /// <returns>The loaded native ignore metadata.</returns>
    public static PicketIgnore LoadExisting(string root, IReadOnlyList<string> ignoreFilePaths)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(ignoreFilePaths);

        var paths = new List<string>();
        if (Directory.Exists(root))
        {
            paths.Add(Path.Combine(root, ".picketignore"));
        }

        for (int i = 0; i < ignoreFilePaths.Count; i++)
        {
            paths.Add(ignoreFilePaths[i]);
        }

        return LoadExisting(paths);
    }

    /// <summary>
    /// Loads native ignore metadata from every existing file path in order.
    /// </summary>
    /// <param name="paths">Candidate ignore file paths.</param>
    /// <returns>The loaded native ignore metadata.</returns>
    public static PicketIgnore LoadExisting(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var locations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string path in paths)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            int lineNumber = 0;
            foreach (string line in File.ReadLines(path))
            {
                lineNumber++;
                AddLine(hashes, locations, line, path, lineNumber);
            }
        }

        return hashes.Count == 0 ? Empty : new PicketIgnore(hashes, locations);
    }

    /// <summary>
    /// Parses native ignore metadata from lines.
    /// </summary>
    /// <param name="lines">The lines to parse.</param>
    /// <returns>The parsed native ignore metadata.</returns>
    public static PicketIgnore FromLines(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var locations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in lines)
        {
            AddLine(hashes, locations, line, sourcePath: string.Empty, lineNumber: 0);
        }

        return hashes.Count == 0 ? Empty : new PicketIgnore(hashes, locations);
    }

    /// <summary>
    /// Returns a value indicating whether the supplied content hash is ignored.
    /// </summary>
    /// <param name="content">The content bytes to test.</param>
    /// <returns><see langword="true" /> when the content hash is ignored.</returns>
    public bool IsContentHashIgnored(ReadOnlySpan<byte> content)
    {
        if (_contentSha256Hashes.Count == 0)
        {
            return false;
        }

        return _contentSha256Hashes.Contains(ComputeSha256(content));
    }

    /// <summary>
    /// Returns a value indicating whether the supplied content hash is ignored and records the match for stale-ignore auditing.
    /// </summary>
    /// <param name="content">The content bytes to test.</param>
    /// <returns><see langword="true" /> when the content hash is ignored.</returns>
    public bool TryIgnoreContentHash(ReadOnlySpan<byte> content)
    {
        if (_contentSha256Hashes.Count == 0)
        {
            return false;
        }

        string hash = ComputeSha256(content);
        if (!_contentSha256Hashes.Contains(hash))
        {
            return false;
        }

        _matchedContentSha256Hashes.Add(hash);
        return true;
    }

    /// <summary>
    /// Gets human-readable SHA-256 ignore entries that did not match any recorded content.
    /// </summary>
    /// <returns>The unmatched SHA-256 ignore entries in deterministic order.</returns>
    public List<string> GetUnmatchedContentHashEntries()
    {
        var entries = new List<string>();
        foreach (string hash in _contentSha256Hashes)
        {
            if (_matchedContentSha256Hashes.Contains(hash))
            {
                continue;
            }

            entries.Add(FormatContentHashEntry(hash));
        }

        entries.Sort(StringComparer.OrdinalIgnoreCase);
        return entries;
    }

    private static string ComputeSha256(ReadOnlySpan<byte> content)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(content, hash);
        return Convert.ToHexString(hash);
    }

    private static void AddLine(
        HashSet<string> hashes,
        Dictionary<string, string> locations,
        string line,
        string sourcePath,
        int lineNumber)
    {
        string trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed[0] == '#')
        {
            return;
        }

        if (!trimmed.StartsWith(Sha256Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string hash = TrimInlineComment(trimmed[Sha256Prefix.Length..].Trim());

        if (IsSha256Hex(hash))
        {
            hashes.Add(hash);
            if (!locations.ContainsKey(hash) && !string.IsNullOrEmpty(sourcePath) && lineNumber > 0)
            {
                locations.Add(hash, $"{sourcePath}:{lineNumber.ToString(CultureInfo.InvariantCulture)}");
            }
        }
    }

    private static string TrimInlineComment(string value)
    {
        int commentIndex = value.IndexOf('#', StringComparison.Ordinal);
        if (commentIndex <= 0 || !char.IsWhiteSpace(value[commentIndex - 1]))
        {
            return value;
        }

        return value[..commentIndex].TrimEnd();
    }

    private static bool IsSha256Hex(string value)
    {
        if (value.Length != Sha256HexLength)
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (!char.IsAsciiHexDigit(ch))
            {
                return false;
            }
        }

        return true;
    }

    private static HashSet<string> CreateHashSet(IEnumerable<string> hashes)
    {
        ArgumentNullException.ThrowIfNull(hashes);
        return new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
    }

    private string FormatContentHashEntry(string hash)
    {
        return _contentSha256Locations.TryGetValue(hash, out string? location) && location.Length != 0
            ? $"{location} sha256:{hash}"
            : $"sha256:{hash}";
    }
}
