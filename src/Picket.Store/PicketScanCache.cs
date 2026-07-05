using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using Picket.Engine;

namespace Picket.Store;

/// <summary>
/// Stores and retrieves native scan results for unchanged filesystem blobs.
/// </summary>
public sealed class PicketScanCache
{
    private const string SchemaLine = "picket.scan-cache.v1";
    private const string EntriesDirectoryName = "entries";
    private const string LocksDirectoryName = "locks";

    private readonly string _entriesPath;
    private readonly string _locksPath;

    private PicketScanCache(string rootPath, ScanCacheKey key)
    {
        RootPath = Path.GetFullPath(rootPath);
        Key = key;
        _entriesPath = Path.Combine(RootPath, EntriesDirectoryName);
        _locksPath = Path.Combine(RootPath, LocksDirectoryName);
        Directory.CreateDirectory(_entriesPath);
        Directory.CreateDirectory(_locksPath);
    }

    /// <summary>
    /// Gets the cache root path.
    /// </summary>
    public string RootPath { get; }

    /// <summary>
    /// Gets the scanner configuration key used by this cache.
    /// </summary>
    public ScanCacheKey Key { get; }

    /// <summary>
    /// Opens a scan cache at the supplied root directory.
    /// </summary>
    /// <param name="rootPath">The cache root directory.</param>
    /// <param name="key">The scanner configuration key.</param>
    /// <returns>The opened scan cache.</returns>
    public static PicketScanCache Open(string rootPath, ScanCacheKey key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentNullException.ThrowIfNull(key);
        return new PicketScanCache(rootPath, key);
    }

    /// <summary>
    /// Reads cached findings for a blob and report path when available.
    /// </summary>
    /// <param name="content">The source content bytes.</param>
    /// <param name="fileName">The current logical report path.</param>
    /// <param name="symlinkFile">The current symlink report path, or an empty string.</param>
    /// <param name="findings">The cached findings when the method returns <see langword="true" />.</param>
    /// <returns><see langword="true" /> when a valid cache entry was read; otherwise <see langword="false" />.</returns>
    public bool TryRead(ReadOnlySpan<byte> content, string fileName, string symlinkFile, [NotNullWhen(true)] out List<Finding>? findings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        string blobHash = BlobHasher.ComputeSha256Hex(content);
        string pathHash = BlobHasher.ComputeSha256Hex(fileName);
        string entryPath = CreateEntryPath(blobHash, pathHash);
        findings = null;
        if (!File.Exists(entryPath))
        {
            return false;
        }

        try
        {
            return TryReadEntry(entryPath, blobHash, fileName, symlinkFile, out findings);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
        {
            findings = null;
            return false;
        }
    }

    /// <summary>
    /// Writes findings for a blob and report path.
    /// </summary>
    /// <param name="content">The source content bytes.</param>
    /// <param name="fileName">The logical report path used to produce the findings.</param>
    /// <param name="findings">The findings to cache.</param>
    public void Write(ReadOnlySpan<byte> content, string fileName, IReadOnlyList<Finding> findings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(findings);

        string blobHash = BlobHasher.ComputeSha256Hex(content);
        string pathHash = BlobHasher.ComputeSha256Hex(fileName);
        string entryPath = CreateEntryPath(blobHash, pathHash);
        string? entryDirectory = Path.GetDirectoryName(entryPath);
        if (entryDirectory is not null)
        {
            Directory.CreateDirectory(entryDirectory);
        }

        string lockPath = Path.Combine(_locksPath, string.Concat(blobHash, "-", pathHash, ".lock"));
        using FileStream _ = OpenLock(lockPath);
        string tempPath = string.Concat(entryPath, ".", Environment.ProcessId.ToString(CultureInfo.InvariantCulture), ".", Guid.NewGuid().ToString("N"), ".tmp");
        try
        {
            File.WriteAllText(tempPath, CreateEntry(blobHash, Key.Fingerprint, findings), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(tempPath, entryPath, overwrite: true);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static FileStream OpenLock(string lockPath)
    {
        return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private static string CreateEntry(string blobHash, string keyFingerprint, IReadOnlyList<Finding> findings)
    {
        var builder = new StringBuilder();
        builder.Append(SchemaLine);
        builder.Append('\n');
        builder.Append("key\t");
        builder.Append(TextFieldCodec.Encode(keyFingerprint));
        builder.Append('\n');
        builder.Append("blob\t");
        builder.Append(TextFieldCodec.Encode(blobHash));
        builder.Append('\n');
        for (int i = 0; i < findings.Count; i++)
        {
            CachedFinding.FromFinding(findings[i]).Write(builder);
        }

        return builder.ToString();
    }

    private bool TryReadEntry(
        string entryPath,
        string blobHash,
        string fileName,
        string symlinkFile,
        [NotNullWhen(true)] out List<Finding>? findings)
    {
        findings = null;
        string[] lines = File.ReadAllLines(entryPath);
        if (lines.Length < 3 || !lines[0].Equals(SchemaLine, StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryReadHeader(lines[1], "key", out string key)
            || !key.Equals(Key.Fingerprint, StringComparison.Ordinal)
            || !TryReadHeader(lines[2], "blob", out string storedBlobHash)
            || !storedBlobHash.Equals(blobHash, StringComparison.Ordinal))
        {
            return false;
        }

        var parsedFindings = new List<Finding>(Math.Max(0, lines.Length - 3));
        for (int i = 3; i < lines.Length; i++)
        {
            if (lines[i].Length == 0)
            {
                continue;
            }

            string[] fields = lines[i].Split('\t');
            if (fields.Length == 0 || !fields[0].Equals("finding", StringComparison.Ordinal))
            {
                return false;
            }

            if (!CachedFinding.TryParse(fields.AsSpan(1), out CachedFinding? cachedFinding))
            {
                return false;
            }

            parsedFindings.Add(cachedFinding.ToFinding(fileName, symlinkFile));
        }

        findings = parsedFindings;
        return true;
    }

    private static bool TryReadHeader(string line, string name, out string value)
    {
        value = string.Empty;
        string[] fields = line.Split('\t');
        if (fields.Length < 2 || !fields[0].Equals(name, StringComparison.Ordinal))
        {
            return false;
        }

        value = TextFieldCodec.Decode(fields[1]);
        return true;
    }

    private string CreateEntryPath(string blobHash, string pathHash)
    {
        string shard = blobHash[..2];
        return Path.Combine(_entriesPath, shard, string.Concat(blobHash, "-", pathHash, "-", Key.Fingerprint, ".cache"));
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
