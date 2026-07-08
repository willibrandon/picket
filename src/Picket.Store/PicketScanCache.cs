using Picket.Engine;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Store;

/// <summary>
/// Stores and retrieves native scan results for unchanged filesystem blobs.
/// </summary>
public sealed class PicketScanCache
{
    private const int AuthenticationKeyByteLength = 32;
    private const int DefaultMaxImportEntries = 100_000;
    private const int Sha256HexLength = 64;
    private const long DefaultMaxImportEntryBytes = 100_000_000;
    private const long DefaultMaxImportTotalBytes = 1_000_000_000;
    private const string CacheEntryExtension = ".cache";
    private const string AuthenticationKeyFileName = "scan-cache-auth.key";
    private const string AddressHashHeader = "addressHash";
    private const string AddressModeHeader = "addressMode";
    private const string ContentAddressDiscriminator = "content";
    private const string CreatedUnixTimeSecondsHeader = "createdUnixTimeSeconds";
    private const string EntriesDirectoryName = "entries";
    private const string ExtensionAddressPrefix = "extension:";
    private const string FindingCountHeader = "findingCount";
    private const string LocksDirectoryName = "locks";
    private const string MacHeader = "mac";
    private const string ProductDirectoryName = "Picket";
    private const string SchemaLine = "picket.scan-cache.v2";
    private const string ShardHeader = "shard";
    private const string StorageModeHeader = "storageMode";
    private const UnixFileMode OwnerOnlyDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _entriesPath;
    private readonly string _locksPath;
    private readonly byte[] _authenticationKey;
    private static readonly UTF8Encoding s_utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private PicketScanCache(string rootPath, ScanCacheKey key)
    {
        RootPath = Path.GetFullPath(rootPath);
        Key = key;
        _authenticationKey = LoadOrCreateAuthenticationKey();
        _entriesPath = Path.Combine(RootPath, EntriesDirectoryName);
        _locksPath = Path.Combine(RootPath, LocksDirectoryName);
        CreateOwnerOnlyDirectory(RootPath);
        CreateOwnerOnlyDirectory(_entriesPath);
        CreateOwnerOnlyDirectory(_locksPath);
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
        string addressHash = CreateAddressHash(fileName);
        string entryPath = CreateEntryPath(blobHash, addressHash);
        findings = null;
        if (!File.Exists(entryPath))
        {
            return false;
        }

        try
        {
            return TryReadEntry(entryPath, blobHash, addressHash, fileName, symlinkFile, out findings);
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

        try
        {
            string blobHash = BlobHasher.ComputeSha256Hex(content);
            string addressHash = CreateAddressHash(fileName);
            string shard = CreateEntryShard(blobHash);
            string entryPath = CreateEntryPath(blobHash, addressHash);
            string? entryDirectory = Path.GetDirectoryName(entryPath);
            if (entryDirectory is not null)
            {
                CreateOwnerOnlyDirectory(entryDirectory);
            }

            string lockPath = Path.Combine(_locksPath, string.Concat(blobHash, "-", addressHash, ".lock"));
            using FileStream _ = OpenLock(lockPath);
            string tempPath = string.Concat(entryPath, ".", Environment.ProcessId.ToString(CultureInfo.InvariantCulture), ".", Guid.NewGuid().ToString("N"), ".tmp");
            try
            {
                WriteOwnerOnlyText(tempPath, CreateAuthenticatedEntry(blobHash, addressHash, shard, Key.Fingerprint, Key.AddressMode, Key.StorageMode, findings));
                File.Move(tempPath, entryPath, overwrite: true);
                SetOwnerOnlyFile(entryPath);
            }
            finally
            {
                TryDelete(tempPath);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    /// <summary>
    /// Exports current scanner-key cache entries to a portable zip archive.
    /// </summary>
    /// <param name="archivePath">The destination archive path.</param>
    /// <returns>The number of exported entries.</returns>
    public int Export(string archivePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        string fullArchivePath = Path.GetFullPath(archivePath);
        string? archiveDirectory = Path.GetDirectoryName(fullArchivePath);
        if (!string.IsNullOrEmpty(archiveDirectory))
        {
            Directory.CreateDirectory(archiveDirectory);
        }

        int exported = 0;
        string tempPath = CreateTempPath(fullArchivePath);
        try
        {
            using (var archiveStream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var archive = new ZipArchive(archiveStream, ZipArchiveMode.Create))
            {
                foreach (string entryPath in EnumerateEntryFiles())
                {
                    if (!TryCreateArchiveEntryName(entryPath, out string? entryName, out string blobHash, out string addressHash, out string shard)
                        || !IsValidEntryFile(entryPath, blobHash, addressHash, shard, Key.Fingerprint, Key.AddressMode, Key.StorageMode))
                    {
                        continue;
                    }

                    try
                    {
                        DateTime lastWriteTimeUtc = File.GetLastWriteTimeUtc(entryPath);
                        using FileStream input = OpenSequentialRead(entryPath);
                        ZipArchiveEntry archiveEntry = archive.CreateEntry(entryName, CompressionLevel.Fastest);
                        archiveEntry.LastWriteTime = new DateTimeOffset(lastWriteTimeUtc, TimeSpan.Zero);
                        using Stream output = archiveEntry.Open();
                        input.CopyTo(output);
                        exported++;
                    }
                    catch (IOException)
                    {
                    }
                    catch (UnauthorizedAccessException)
                    {
                    }
                }
            }

            File.Move(tempPath, fullArchivePath, overwrite: true);
            return exported;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    /// <summary>
    /// Imports current scanner-key cache entries from a portable zip archive.
    /// </summary>
    /// <param name="archivePath">The source archive path.</param>
    /// <returns>The number of imported entries.</returns>
    public int Import(string archivePath)
    {
        return Import(archivePath, DefaultMaxImportEntryBytes, DefaultMaxImportEntries, DefaultMaxImportTotalBytes);
    }

    /// <summary>
    /// Imports current scanner-key cache entries from a portable zip archive.
    /// </summary>
    /// <param name="archivePath">The source archive path.</param>
    /// <param name="maxEntryBytes">The maximum decompressed bytes allowed for a single imported entry.</param>
    /// <returns>The number of imported entries.</returns>
    public int Import(string archivePath, long maxEntryBytes)
    {
        return Import(archivePath, maxEntryBytes, DefaultMaxImportEntries, DefaultMaxImportTotalBytes);
    }

    /// <summary>
    /// Imports current scanner-key cache entries from a portable zip archive.
    /// </summary>
    /// <param name="archivePath">The source archive path.</param>
    /// <param name="maxEntryBytes">The maximum decompressed bytes allowed for a single imported entry.</param>
    /// <param name="maxEntries">The maximum non-directory entries allowed in the archive.</param>
    /// <param name="maxTotalBytes">The maximum aggregate decompressed bytes allowed for imported current-key entries.</param>
    /// <returns>The number of imported entries.</returns>
    public int Import(string archivePath, long maxEntryBytes, int maxEntries, long maxTotalBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxEntryBytes, 0);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxEntries, 0);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxTotalBytes, 0);

        int imported = 0;
        int entryCount = 0;
        long totalImportedBytes = 0;
        using var archiveStream = new FileStream(Path.GetFullPath(archivePath), FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read);
        foreach (ZipArchiveEntry archiveEntry in archive.Entries)
        {
            if (IsDirectoryArchiveEntry(archiveEntry))
            {
                continue;
            }

            entryCount++;
            if (entryCount > maxEntries)
            {
                throw new FormatException($"Cache archive exceeds maximum entry count: {maxEntries.ToString(CultureInfo.InvariantCulture)}");
            }

            if (!TryParseArchiveEntryName(
                archiveEntry.FullName,
                out string blobHash,
                out string addressHash,
                out string shard,
                out bool isCurrentKey))
            {
                throw new FormatException($"Invalid cache archive entry path: {archiveEntry.FullName}");
            }

            if (!isCurrentKey)
            {
                continue;
            }

            if (archiveEntry.Length > maxEntryBytes)
            {
                throw new FormatException($"Cache archive entry exceeds maximum decompressed size: {archiveEntry.FullName}");
            }

            if (ExceedsBudget(totalImportedBytes, archiveEntry.Length, maxTotalBytes))
            {
                throw new FormatException($"Cache archive exceeds maximum decompressed size: {archiveEntry.FullName}");
            }

            string entryPath = Path.Combine(_entriesPath, shard, CreateEntryFileName(blobHash, addressHash, Key.Fingerprint));
            string fullEntryPath = Path.GetFullPath(entryPath);
            if (!IsWithinDirectory(fullEntryPath, _entriesPath))
            {
                throw new FormatException($"Invalid cache archive entry path: {archiveEntry.FullName}");
            }

            string? entryDirectory = Path.GetDirectoryName(fullEntryPath);
            if (entryDirectory is not null)
            {
                CreateOwnerOnlyDirectory(entryDirectory);
            }

            string lockPath = Path.Combine(_locksPath, string.Concat(blobHash, "-", addressHash, ".lock"));
            using FileStream _ = OpenLock(lockPath);
            string tempPath = CreateTempPath(fullEntryPath);
            try
            {
                long copiedBytes;
                using (Stream input = archiveEntry.Open())
                using (FileStream output = OpenOwnerOnlyNewFile(tempPath))
                {
                    copiedBytes = CopyArchiveEntryWithinLimit(input, output, maxEntryBytes, archiveEntry.FullName);
                }

                if (ExceedsBudget(totalImportedBytes, copiedBytes, maxTotalBytes))
                {
                    throw new FormatException($"Cache archive exceeds maximum decompressed size: {archiveEntry.FullName}");
                }

                if (!IsValidEntryFile(tempPath, blobHash, addressHash, shard, Key.Fingerprint, Key.AddressMode, Key.StorageMode))
                {
                    throw new FormatException($"Invalid cache archive entry content: {archiveEntry.FullName}");
                }

                File.Move(tempPath, fullEntryPath, overwrite: true);
                SetOwnerOnlyFile(fullEntryPath);
                TrySetLastWriteTimeUtc(fullEntryPath, archiveEntry);
                imported++;
                totalImportedBytes += copiedBytes;
            }
            finally
            {
                TryDelete(tempPath);
            }
        }

        return imported;
    }

    private static long CopyArchiveEntryWithinLimit(Stream input, Stream output, long maxBytes, string entryName)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long totalRead = 0;
            int read;
            while ((read = input.Read(buffer)) != 0)
            {
                long projectedTotal = totalRead + read;
                if (projectedTotal > maxBytes)
                {
                    throw new FormatException($"Cache archive entry exceeds maximum decompressed size: {entryName}");
                }

                output.Write(buffer.AsSpan(0, read));
                totalRead = projectedTotal;
            }

            return totalRead;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static bool ExceedsBudget(long current, long addition, long max)
    {
        return addition > max || current > max - addition;
    }

    /// <summary>
    /// Returns summary statistics for the cache entries currently on disk.
    /// </summary>
    /// <returns>The cache statistics.</returns>
    public PicketScanCacheStats GetStats()
    {
        int entryCount = 0;
        int currentKeyEntryCount = 0;
        long totalBytes = 0;
        foreach (string entryPath in EnumerateEntryFiles())
        {
            entryCount++;
            if (IsCurrentKeyEntryPath(entryPath))
            {
                currentKeyEntryCount++;
            }

            long length = new FileInfo(entryPath).Length;
            totalBytes = long.MaxValue - totalBytes < length
                ? long.MaxValue
                : totalBytes + length;
        }

        return new PicketScanCacheStats(RootPath, entryCount, currentKeyEntryCount, totalBytes);
    }

    /// <summary>
    /// Removes entries that belong to older scanner configuration keys.
    /// </summary>
    /// <returns>The number of deleted entries.</returns>
    public int PruneOtherKeys()
    {
        return Prune(entryPath => !IsCurrentKeyEntryPath(entryPath));
    }

    /// <summary>
    /// Removes entries older than the supplied age.
    /// </summary>
    /// <param name="maxAge">The maximum retained entry age.</param>
    /// <returns>The number of deleted entries.</returns>
    public int PruneOlderThan(TimeSpan maxAge)
    {
        if (maxAge < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge), maxAge, "Value must be non-negative.");
        }

        DateTime cutoffUtc = DateTime.UtcNow - maxAge;
        return Prune(entryPath => File.GetLastWriteTimeUtc(entryPath) < cutoffUtc);
    }

    private static FileStream OpenLock(string lockPath)
    {
        FileStream stream = OpenOwnerOnlyFile(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
        SetOwnerOnlyFile(lockPath);
        return stream;
    }

    private static byte[] LoadOrCreateAuthenticationKey()
    {
        string keyPath = GetAuthenticationKeyPath();
        string? keyDirectory = Path.GetDirectoryName(keyPath);
        if (!string.IsNullOrEmpty(keyDirectory))
        {
            CreateOwnerOnlyDirectory(keyDirectory);
        }

        try
        {
            if (File.Exists(keyPath))
            {
                byte[] existing = File.ReadAllBytes(keyPath);
                if (existing.Length == AuthenticationKeyByteLength)
                {
                    SetOwnerOnlyFile(keyPath);
                    return existing;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        byte[] key = RandomNumberGenerator.GetBytes(AuthenticationKeyByteLength);
        string tempPath = CreateTempPath(keyPath);
        try
        {
            using (FileStream stream = OpenOwnerOnlyNewFile(tempPath))
            {
                stream.Write(key);
            }

            try
            {
                File.Move(tempPath, keyPath, overwrite: false);
                SetOwnerOnlyFile(keyPath);
                return key;
            }
            catch (IOException)
            {
                byte[] existing = File.ReadAllBytes(keyPath);
                if (existing.Length == AuthenticationKeyByteLength)
                {
                    SetOwnerOnlyFile(keyPath);
                    return existing;
                }

                File.Move(tempPath, keyPath, overwrite: true);
                SetOwnerOnlyFile(keyPath);
                return key;
            }
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static string GetAuthenticationKeyPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            string? stateHome = Environment.GetEnvironmentVariable("XDG_STATE_HOME");
            if (!string.IsNullOrWhiteSpace(stateHome))
            {
                return Path.Combine(stateHome, "picket", AuthenticationKeyFileName);
            }
        }

        string basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(basePath))
        {
            basePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        if (string.IsNullOrWhiteSpace(basePath))
        {
            basePath = Path.GetTempPath();
        }

        return Path.Combine(basePath, ProductDirectoryName, AuthenticationKeyFileName);
    }

    private static FileStream OpenOwnerOnlyNewFile(string path)
    {
        return OpenOwnerOnlyFile(path, FileMode.CreateNew, FileAccess.Write);
    }

    private static FileStream OpenOwnerOnlyFile(string path, FileMode mode, FileAccess access)
    {
        var options = new FileStreamOptions
        {
            Access = access,
            Mode = mode,
            Share = FileShare.None,
            Options = FileOptions.SequentialScan,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = OwnerOnlyFileMode;
        }

        return new FileStream(path, options);
    }

    private static void WriteOwnerOnlyText(string path, string text)
    {
        using FileStream stream = OpenOwnerOnlyNewFile(path);
        using var writer = new StreamWriter(stream, s_utf8NoBom);
        writer.Write(text);
    }

    private static void CreateOwnerOnlyDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, OwnerOnlyDirectoryMode);
        }
    }

    private static void SetOwnerOnlyFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, OwnerOnlyFileMode);
        }
    }

    private static FileStream OpenSequentialRead(string path)
    {
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 81920, FileOptions.SequentialScan);
    }

    private string CreateAuthenticatedEntry(
        string blobHash,
        string addressHash,
        string shard,
        string keyFingerprint,
        ScanCacheAddressMode addressMode,
        ScanCacheStorageMode storageMode,
        IReadOnlyList<Finding> findings)
    {
        string body = CreateEntryBody(blobHash, addressHash, shard, keyFingerprint, addressMode, storageMode, findings);
        return string.Concat(body, MacHeader, '\t', ComputeEntryMac(body), '\n');
    }

    private static string CreateEntryBody(
        string blobHash,
        string addressHash,
        string shard,
        string keyFingerprint,
        ScanCacheAddressMode addressMode,
        ScanCacheStorageMode storageMode,
        IReadOnlyList<Finding> findings)
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
        builder.Append(AddressHashHeader);
        builder.Append('\t');
        builder.Append(addressHash);
        builder.Append('\n');
        builder.Append(ShardHeader);
        builder.Append('\t');
        builder.Append(shard);
        builder.Append('\n');
        builder.Append(CreatedUnixTimeSecondsHeader);
        builder.Append('\t');
        builder.Append(DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        builder.Append('\n');
        builder.Append(AddressModeHeader);
        builder.Append('\t');
        builder.Append(addressMode.ToString());
        builder.Append('\n');
        builder.Append(StorageModeHeader);
        builder.Append('\t');
        builder.Append(storageMode.ToString());
        builder.Append('\n');
        builder.Append(FindingCountHeader);
        builder.Append('\t');
        builder.Append(findings.Count.ToString(CultureInfo.InvariantCulture));
        builder.Append('\n');
        for (int i = 0; i < findings.Count; i++)
        {
            CachedFinding.FromFinding(findings[i], storageMode).Write(builder);
        }

        return builder.ToString();
    }

    private bool TryReadEntry(
        string entryPath,
        string blobHash,
        string addressHash,
        string fileName,
        string symlinkFile,
        [NotNullWhen(true)] out List<Finding>? findings)
    {
        findings = null;
        if (!TryReadAuthenticatedEntryLines(entryPath, out string[]? lines)
            || lines.Length < 3
            || !lines[0].Equals(SchemaLine, StringComparison.Ordinal))
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

        ScanCacheAddressMode? entryAddressMode = null;
        ScanCacheStorageMode? entryStorageMode = null;
        string? entryAddressHash = null;
        string? entryShard = null;
        int? expectedFindingCount = null;
        bool findingSectionStarted = false;
        var parsedFindings = new List<Finding>(Math.Max(0, lines.Length - 3));
        for (int i = 3; i < lines.Length; i++)
        {
            if (lines[i].Length == 0)
            {
                continue;
            }

            string[] fields = lines[i].Split('\t');
            if (fields.Length == 0)
            {
                return false;
            }

            if (!fields[0].Equals("finding", StringComparison.Ordinal))
            {
                if (findingSectionStarted || !TryReadMetadata(fields, ref entryAddressMode, ref entryStorageMode, ref entryAddressHash, ref entryShard, ref expectedFindingCount))
                {
                    return false;
                }

                continue;
            }

            findingSectionStarted = true;
            if (!CachedFinding.TryParse(fields.AsSpan(1), out CachedFinding? cachedFinding))
            {
                return false;
            }

            parsedFindings.Add(cachedFinding.ToFinding(fileName, symlinkFile, blobHash));
        }

        if ((entryAddressMode ?? ScanCacheAddressMode.Path) != Key.AddressMode
            || (entryStorageMode ?? ScanCacheStorageMode.Raw) != Key.StorageMode)
        {
            return false;
        }

        if (!addressHash.Equals(entryAddressHash, StringComparison.Ordinal)
            || !CreateEntryShard(blobHash).Equals(entryShard, StringComparison.Ordinal))
        {
            return false;
        }

        if (expectedFindingCount.HasValue && expectedFindingCount.Value != parsedFindings.Count)
        {
            return false;
        }

        findings = parsedFindings;
        return true;
    }

    private static bool TryReadMetadata(
        string[] fields,
        ref ScanCacheAddressMode? entryAddressMode,
        ref ScanCacheStorageMode? entryStorageMode,
        ref string? entryAddressHash,
        ref string? entryShard,
        ref int? expectedFindingCount)
    {
        if (fields.Length != 2)
        {
            return false;
        }

        if (fields[0].Equals(CreatedUnixTimeSecondsHeader, StringComparison.Ordinal))
        {
            return long.TryParse(fields[1], CultureInfo.InvariantCulture, out long value) && value >= 0;
        }

        if (fields[0].Equals(AddressModeHeader, StringComparison.Ordinal))
        {
            if (!Enum.TryParse(fields[1], ignoreCase: false, out ScanCacheAddressMode value)
                || value is not (ScanCacheAddressMode.Path or ScanCacheAddressMode.FileExtension or ScanCacheAddressMode.Content))
            {
                return false;
            }

            entryAddressMode = value;
            return true;
        }

        if (fields[0].Equals(AddressHashHeader, StringComparison.Ordinal))
        {
            if (!IsSha256Hex(fields[1]))
            {
                return false;
            }

            entryAddressHash = fields[1];
            return true;
        }

        if (fields[0].Equals(ShardHeader, StringComparison.Ordinal))
        {
            if (fields[1].Length != 2 || !IsHex(fields[1][0]) || !IsHex(fields[1][1]))
            {
                return false;
            }

            entryShard = fields[1];
            return true;
        }

        if (fields[0].Equals(StorageModeHeader, StringComparison.Ordinal))
        {
            if (!Enum.TryParse(fields[1], ignoreCase: false, out ScanCacheStorageMode value)
                || value is not (ScanCacheStorageMode.Raw or ScanCacheStorageMode.SecretHashOnly))
            {
                return false;
            }

            entryStorageMode = value;
            return true;
        }

        if (fields[0].Equals(FindingCountHeader, StringComparison.Ordinal))
        {
            if (!int.TryParse(fields[1], CultureInfo.InvariantCulture, out int value) || value < 0)
            {
                return false;
            }

            expectedFindingCount = value;
            return true;
        }

        return false;
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

    private static bool IsDirectoryArchiveEntry(ZipArchiveEntry archiveEntry)
    {
        return archiveEntry.FullName.EndsWith('/');
    }

    private bool TryParseArchiveEntryName(
        string entryName,
        out string blobHash,
        out string addressHash,
        out string shard,
        out bool isCurrentKey)
    {
        blobHash = string.Empty;
        addressHash = string.Empty;
        shard = string.Empty;
        isCurrentKey = false;

        string normalizedEntryName = entryName.Replace('\\', '/');
        if (normalizedEntryName.Length == 0
            || normalizedEntryName.StartsWith('/')
            || normalizedEntryName.Contains(':'))
        {
            return false;
        }

        string[] segments = normalizedEntryName.Split('/');
        if (segments.Length != 3
            || !segments[0].Equals(EntriesDirectoryName, StringComparison.Ordinal)
            || segments[1].Length != 2
            || !TryParseEntryFileName(segments[2], out blobHash, out addressHash, out string keyFingerprint)
            || !segments[1].Equals(blobHash[..2], StringComparison.Ordinal))
        {
            return false;
        }

        shard = segments[1];
        isCurrentKey = keyFingerprint.Equals(Key.Fingerprint, StringComparison.Ordinal);
        return true;
    }

    private string CreateEntryPath(string blobHash, string addressHash)
    {
        string shard = CreateEntryShard(blobHash);
        return Path.Combine(_entriesPath, shard, CreateEntryFileName(blobHash, addressHash, Key.Fingerprint));
    }

    private static string CreateEntryShard(string blobHash)
    {
        return blobHash[..2];
    }

    private string CreateAddressHash(string fileName)
    {
        return Key.AddressMode switch
        {
            ScanCacheAddressMode.Path => BlobHasher.ComputeSha256Hex(fileName),
            ScanCacheAddressMode.FileExtension => BlobHasher.ComputeSha256Hex(CreateExtensionAddress(fileName)),
            ScanCacheAddressMode.Content => BlobHasher.ComputeSha256Hex(ContentAddressDiscriminator),
            _ => throw new InvalidOperationException($"Unsupported cache address mode: {Key.AddressMode}."),
        };
    }

    private static string CreateExtensionAddress(string fileName)
    {
        return string.Concat(ExtensionAddressPrefix, Path.GetExtension(fileName).ToLowerInvariant());
    }

    private IEnumerable<string> EnumerateEntryFiles()
    {
        return Directory.Exists(_entriesPath)
            ? Directory.EnumerateFiles(_entriesPath, "*.cache", SearchOption.AllDirectories)
            : [];
    }

    private bool IsCurrentKeyEntryPath(string entryPath)
    {
        string fileName = Path.GetFileName(entryPath);
        return fileName.EndsWith(string.Concat("-", Key.Fingerprint, CacheEntryExtension), StringComparison.Ordinal);
    }

    private int Prune(Func<string, bool> shouldDelete)
    {
        int deleted = 0;
        foreach (string entryPath in EnumerateEntryFiles())
        {
            try
            {
                if (shouldDelete(entryPath) && TryDelete(entryPath))
                {
                    deleted++;
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return deleted;
    }

    private bool TryCreateArchiveEntryName(
        string entryPath,
        [NotNullWhen(true)] out string? entryName,
        out string blobHash,
        out string addressHash,
        out string shard)
    {
        entryName = null;
        blobHash = string.Empty;
        addressHash = string.Empty;
        shard = string.Empty;
        if (!IsCurrentKeyEntryPath(entryPath))
        {
            return false;
        }

        string? entryDirectory = Path.GetDirectoryName(entryPath);
        if (entryDirectory is null)
        {
            return false;
        }

        shard = Path.GetFileName(entryDirectory);
        string fileName = Path.GetFileName(entryPath);
        if (!TryParseEntryFileName(fileName, out blobHash, out addressHash, out string keyFingerprint)
            || !keyFingerprint.Equals(Key.Fingerprint, StringComparison.Ordinal)
            || !shard.Equals(blobHash[..2], StringComparison.Ordinal))
        {
            return false;
        }

        entryName = string.Concat(EntriesDirectoryName, "/", shard, "/", fileName);
        return true;
    }

    private static string CreateEntryFileName(string blobHash, string addressHash, string keyFingerprint)
    {
        return string.Concat(blobHash, "-", addressHash, "-", keyFingerprint, CacheEntryExtension);
    }

    private static string CreateTempPath(string path)
    {
        return string.Concat(
            path,
            ".",
            Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
            ".",
            Guid.NewGuid().ToString("N"),
            ".tmp");
    }

    private static bool TryParseEntryFileName(
        string fileName,
        out string blobHash,
        out string addressHash,
        out string keyFingerprint)
    {
        blobHash = string.Empty;
        addressHash = string.Empty;
        keyFingerprint = string.Empty;
        if (!fileName.EndsWith(CacheEntryExtension, StringComparison.Ordinal)
            || fileName.Length != Sha256HexLength + 1 + Sha256HexLength + 1 + Sha256HexLength + CacheEntryExtension.Length
            || fileName[Sha256HexLength] != '-'
            || fileName[Sha256HexLength + 1 + Sha256HexLength] != '-')
        {
            return false;
        }

        blobHash = fileName[..Sha256HexLength];
        addressHash = fileName.Substring(Sha256HexLength + 1, Sha256HexLength);
        keyFingerprint = fileName.Substring(Sha256HexLength + 1 + Sha256HexLength + 1, Sha256HexLength);
        return IsSha256Hex(blobHash) && IsSha256Hex(addressHash) && IsSha256Hex(keyFingerprint);
    }

    private bool IsValidEntryFile(
        string entryPath,
        string blobHash,
        string addressHash,
        string shard,
        string keyFingerprint,
        ScanCacheAddressMode addressMode,
        ScanCacheStorageMode storageMode)
    {
        try
        {
            if (!TryReadAuthenticatedEntryLines(entryPath, out string[]? lines)
                || lines.Length < 3
                || !lines[0].Equals(SchemaLine, StringComparison.Ordinal)
                || !TryReadHeader(lines[1], "key", out string storedKeyFingerprint)
                || !storedKeyFingerprint.Equals(keyFingerprint, StringComparison.Ordinal)
                || !TryReadHeader(lines[2], "blob", out string storedBlobHash)
                || !storedBlobHash.Equals(blobHash, StringComparison.Ordinal))
            {
                return false;
            }

            ScanCacheAddressMode? entryAddressMode = null;
            ScanCacheStorageMode? entryStorageMode = null;
            string? entryAddressHash = null;
            string? entryShard = null;
            int? expectedFindingCount = null;
            bool findingSectionStarted = false;
            int parsedFindingCount = 0;
            for (int i = 3; i < lines.Length; i++)
            {
                if (lines[i].Length == 0)
                {
                    continue;
                }

                string[] fields = lines[i].Split('\t');
                if (!fields[0].Equals("finding", StringComparison.Ordinal))
                {
                    if (findingSectionStarted || !TryReadMetadata(fields, ref entryAddressMode, ref entryStorageMode, ref entryAddressHash, ref entryShard, ref expectedFindingCount))
                    {
                        return false;
                    }

                    continue;
                }

                findingSectionStarted = true;
                if (!CachedFinding.TryParse(fields.AsSpan(1), out _))
                {
                    return false;
                }

                parsedFindingCount++;
            }

            return (entryAddressMode ?? ScanCacheAddressMode.Path) == addressMode
                && (entryStorageMode ?? ScanCacheStorageMode.Raw) == storageMode
                && addressHash.Equals(entryAddressHash, StringComparison.Ordinal)
                && shard.Equals(entryShard, StringComparison.Ordinal)
                && (!expectedFindingCount.HasValue || expectedFindingCount.Value == parsedFindingCount);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
        {
            return false;
        }
    }

    private bool TryReadAuthenticatedEntryLines(string entryPath, [NotNullWhen(true)] out string[]? lines)
    {
        lines = null;
        string text = File.ReadAllText(entryPath);
        if (!TrySplitAuthenticatedEntry(text, out string body, out string mac))
        {
            return false;
        }

        string expectedMac = ComputeEntryMac(body);
        if (!FixedTimeEqualsHex(expectedMac, mac))
        {
            return false;
        }

        lines = body.Split('\n');
        return true;
    }

    private static bool TrySplitAuthenticatedEntry(string text, out string body, out string mac)
    {
        body = string.Empty;
        mac = string.Empty;
        if (text.Length == 0 || text[^1] != '\n')
        {
            return false;
        }

        int macLineStart = text.LastIndexOf('\n', text.Length - 2) + 1;
        if (macLineStart <= 0)
        {
            return false;
        }

        ReadOnlySpan<char> macLine = text.AsSpan(macLineStart, text.Length - macLineStart - 1);
        string header = string.Concat(MacHeader, "\t");
        if (!macLine.StartsWith(header, StringComparison.Ordinal))
        {
            return false;
        }

        body = text[..macLineStart];
        mac = macLine[header.Length..].ToString();
        return IsSha256Hex(mac);
    }

    private string ComputeEntryMac(string body)
    {
        byte[] bodyBytes = s_utf8NoBom.GetBytes(body);
        byte[] macBytes = HMACSHA256.HashData(_authenticationKey, bodyBytes);
        return Convert.ToHexStringLower(macBytes);
    }

    private static bool FixedTimeEqualsHex(string expected, string actual)
    {
        return expected.Length == actual.Length
            && CryptographicOperations.FixedTimeEquals(
                s_utf8NoBom.GetBytes(expected),
                s_utf8NoBom.GetBytes(actual));
    }

    private static bool IsSha256Hex(ReadOnlySpan<char> value)
    {
        if (value.Length != Sha256HexLength)
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (ch is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHex(char value)
    {
        return value is >= '0' and <= '9' or >= 'a' and <= 'f';
    }

    private static bool IsWithinDirectory(string path, string directory)
    {
        string fullDirectory = EnsureTrailingDirectorySeparator(Path.GetFullPath(directory));
        return path.StartsWith(fullDirectory, PathComparison);
    }

    private static string EnsureTrailingDirectorySeparator(string path)
    {
        return Path.EndsInDirectorySeparator(path)
            ? path
            : string.Concat(path, Path.DirectorySeparatorChar);
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static void TrySetLastWriteTimeUtc(string path, ZipArchiveEntry archiveEntry)
    {
        try
        {
            File.SetLastWriteTimeUtc(path, archiveEntry.LastWriteTime.UtcDateTime);
        }
        catch (ArgumentOutOfRangeException)
        {
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                return true;
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return false;
    }
}
