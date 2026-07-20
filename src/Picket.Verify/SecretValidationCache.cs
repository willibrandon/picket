using Picket.Security;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Verify;

/// <summary>
/// Stores live validation results without storing raw secrets.
/// </summary>
public sealed class SecretValidationCache
{
    private const int FileOperationRetryCount = 20;
    private const int FileOperationRetryDelayMilliseconds = 10;
    private const int Sha256HexLength = 64;
    private const string AuthenticationKeyFileName = "validation-cache-auth.key";
    private const string CacheFingerprintHeader = "cacheFingerprint";
    private const string EntriesDirectoryName = "entries";
    private const string EvidenceHeader = "evidence";
    private const string ExpiresUnixTimeSecondsHeader = "expiresUnixTimeSeconds";
    private const string IdentityHeader = "identity";
    private const string KeyHeader = "key";
    private const string LocksDirectoryName = "locks";
    private const string LowerHex = "0123456789abcdef";
    private const string MacHeader = "mac";
    private const string ReasonHeader = "reason";
    private const string ReachableResourcesHeader = "reachableResources";
    private const string SchemaLine = "picket.validation-cache.v2";
    private const string ScopesHeader = "scopes";
    private const string StateHeader = "state";
    private readonly string _entriesPath;
    private readonly string _locksPath;
    private readonly byte[] _authenticationKey;
    private static readonly UTF8Encoding s_utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private SecretValidationCache(string rootPath, string cacheFingerprint)
    {
        RootPath = Path.GetFullPath(rootPath);
        CacheFingerprintSha256 = ComputeSha256Hex(cacheFingerprint);
        _authenticationKey = PicketStateProtectionKey.LoadOrCreate(AuthenticationKeyFileName);
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
    /// Gets the SHA-256 hash of the caller-supplied cache fingerprint.
    /// </summary>
    public string CacheFingerprintSha256 { get; }

    /// <summary>
    /// Opens a validation cache at the supplied root directory.
    /// </summary>
    /// <param name="rootPath">The cache root directory.</param>
    /// <param name="cacheFingerprint">The non-secret rule, provider, and configuration fingerprint for invalidation.</param>
    /// <returns>The opened validation cache.</returns>
    public static SecretValidationCache Open(string rootPath, string cacheFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheFingerprint);

        return new SecretValidationCache(rootPath, cacheFingerprint);
    }

    /// <summary>
    /// Reads a cached validation result when the entry exists, matches the active fingerprint, and has not expired.
    /// </summary>
    /// <param name="key">The validation cache key.</param>
    /// <param name="now">The current time used for expiration checks.</param>
    /// <param name="result">The cached result when the method returns <see langword="true" />.</param>
    /// <returns><see langword="true" /> when a valid cached result was read; otherwise <see langword="false" />.</returns>
    public bool TryRead(SecretValidationCacheKey key, DateTimeOffset now, [NotNullWhen(true)] out SecretValidationResult? result)
    {
        ArgumentNullException.ThrowIfNull(key);

        result = null;
        string entryPath = CreateEntryPath(key);
        if (!File.Exists(entryPath))
        {
            return false;
        }

        try
        {
            return TryReadEntry(entryPath, key, now, out result);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException or ArgumentException)
        {
            result = null;
            return false;
        }
    }

    /// <summary>
    /// Writes a validation result to the cache.
    /// </summary>
    /// <param name="key">The validation cache key.</param>
    /// <param name="result">The result to cache.</param>
    /// <param name="expiresAtUtc">The UTC time when the cached result expires.</param>
    public void Write(SecretValidationCacheKey key, SecretValidationResult result, DateTimeOffset expiresAtUtc)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(result);

        string entryPath = CreateEntryPath(key);
        string? entryDirectory = Path.GetDirectoryName(entryPath);
        if (entryDirectory is not null)
        {
            CreateOwnerOnlyDirectory(entryDirectory);
        }

        string lockPath = Path.Combine(_locksPath, string.Concat(key.Fingerprint, ".lock"));
        using FileStream _ = OpenLock(lockPath);
        string tempPath = string.Concat(entryPath, ".", Environment.ProcessId.ToString(CultureInfo.InvariantCulture), ".", Guid.NewGuid().ToString("N"), ".tmp");
        try
        {
            WriteOwnerOnlyText(tempPath, CreateAuthenticatedEntry(key, result, expiresAtUtc));
            File.Move(tempPath, entryPath, overwrite: true);
            SetOwnerOnlyFile(entryPath);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    /// <summary>
    /// Deletes expired or unreadable cache entries.
    /// </summary>
    /// <param name="now">The current time used for expiration checks.</param>
    /// <returns>The number of deleted entries.</returns>
    public int PruneExpired(DateTimeOffset now)
    {
        int deleted = 0;
        string[] entryPaths;
        try
        {
            entryPaths = [.. EnumerateEntryFiles()];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return 0;
        }

        foreach (string entryPath in entryPaths)
        {
            try
            {
                if (ShouldPruneEntry(entryPath, now) && TryDelete(entryPath))
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
            catch (FormatException)
            {
            }
            catch (ArgumentException)
            {
            }
        }

        return deleted;
    }

    private static FileStream OpenLock(string lockPath)
    {
        IOException? lastException = null;
        for (int attempt = 0; attempt < FileOperationRetryCount; attempt++)
        {
            try
            {
                FileStream stream = OpenOwnerOnlyFile(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
                SetOwnerOnlyFile(lockPath);
                return stream;
            }
            catch (IOException exception)
            {
                lastException = exception;
                Thread.Sleep(FileOperationRetryDelayMilliseconds);
            }
        }

        throw new IOException("Timed out while acquiring the validation cache lock.", lastException);
    }

    private string CreateAuthenticatedEntry(SecretValidationCacheKey key, SecretValidationResult result, DateTimeOffset expiresAtUtc)
    {
        string body = CreateEntry(key, result, expiresAtUtc);
        return string.Concat(body, MacHeader, '\t', ComputeEntryMac(body), '\n');
    }

    private string CreateEntry(SecretValidationCacheKey key, SecretValidationResult result, DateTimeOffset expiresAtUtc)
    {
        var builder = new StringBuilder();
        builder.Append(SchemaLine);
        builder.Append('\n');
        AppendHeader(builder, CacheFingerprintHeader, CacheFingerprintSha256);
        AppendHeader(builder, KeyHeader, key.Fingerprint);
        AppendHeader(builder, ExpiresUnixTimeSecondsHeader, expiresAtUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        AppendHeader(builder, StateHeader, SecretValidationResult.ToReportValue(result.State));
        AppendHeader(builder, ReasonHeader, Encode(result.Reason));
        AppendHeader(builder, IdentityHeader, Encode(result.Identity));
        AppendHeader(builder, ScopesHeader, EncodeList(result.Scopes));
        AppendHeader(builder, ReachableResourcesHeader, EncodeList(result.ReachableResources));
        AppendHeader(builder, EvidenceHeader, EncodeList(result.Evidence));
        return builder.ToString();
    }

    private static void AppendHeader(StringBuilder builder, string name, string value)
    {
        builder.Append(name);
        builder.Append('\t');
        builder.Append(value);
        builder.Append('\n');
    }

    private static bool TryParseState(string value, out SecretValidationState state)
    {
        state = value switch
        {
            "active" => SecretValidationState.Active,
            "inactive" => SecretValidationState.Inactive,
            "skipped" => SecretValidationState.Skipped,
            "error" => SecretValidationState.Error,
            "structurally-valid" => SecretValidationState.StructurallyValid,
            "test-credential" => SecretValidationState.TestCredential,
            "invalid" => SecretValidationState.Invalid,
            "unknown" => SecretValidationState.Unknown,
            _ => SecretValidationState.Unknown,
        };

        return value is "active"
            or "inactive"
            or "skipped"
            or "error"
            or "structurally-valid"
            or "test-credential"
            or "invalid"
            or "unknown";
    }

    private static string Encode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }

    private static string Decode(string value)
    {
        return Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }

    private static string EncodeList(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (int i = 0; i < values.Count; i++)
        {
            if (i != 0)
            {
                builder.Append(',');
            }

            builder.Append(Encode(values[i]));
        }

        return builder.ToString();
    }

    private static string[] DecodeList(string value)
    {
        if (value.Length == 0)
        {
            return [];
        }

        string[] encodedValues = value.Split(',');
        var values = new string[encodedValues.Length];
        for (int i = 0; i < encodedValues.Length; i++)
        {
            values[i] = Decode(encodedValues[i]);
        }

        return values;
    }

    private static string ComputeSha256Hex(string value)
    {
        return ComputeSha256Hex(Encoding.UTF8.GetBytes(value));
    }

    private static string ComputeSha256Hex(ReadOnlySpan<byte> content)
    {
        byte[] hash = SHA256.HashData(content);
        return string.Create(hash.Length * 2, hash, static (chars, bytes) =>
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte value = bytes[i];
                chars[i * 2] = LowerHex[value >> 4];
                chars[(i * 2) + 1] = LowerHex[value & 0x0F];
            }
        });
    }

    private bool TryReadEntry(
        string entryPath,
        SecretValidationCacheKey key,
        DateTimeOffset now,
        [NotNullWhen(true)] out SecretValidationResult? result)
    {
        result = null;
        if (!TryReadAuthenticatedEntryLines(entryPath, out string[]? lines)
            || !TryReadHeaders(lines, out Dictionary<string, string>? headers)
            || !headers.TryGetValue(CacheFingerprintHeader, out string? cacheFingerprint)
            || !cacheFingerprint.Equals(CacheFingerprintSha256, StringComparison.Ordinal)
            || !headers.TryGetValue(KeyHeader, out string? storedKey)
            || !storedKey.Equals(key.Fingerprint, StringComparison.Ordinal)
            || !TryReadExpiration(headers, now)
            || !headers.TryGetValue(StateHeader, out string? stateValue)
            || !TryParseState(stateValue, out SecretValidationState state))
        {
            return false;
        }

        string reason = headers.TryGetValue(ReasonHeader, out string? encodedReason)
            ? Decode(encodedReason)
            : string.Empty;
        string identity = headers.TryGetValue(IdentityHeader, out string? encodedIdentity)
            ? Decode(encodedIdentity)
            : string.Empty;
        string[] scopes = headers.TryGetValue(ScopesHeader, out string? encodedScopes)
            ? DecodeList(encodedScopes)
            : [];
        string[] reachableResources = headers.TryGetValue(ReachableResourcesHeader, out string? encodedReachableResources)
            ? DecodeList(encodedReachableResources)
            : [];
        string[] evidence = headers.TryGetValue(EvidenceHeader, out string? encodedEvidence)
            ? DecodeList(encodedEvidence)
            : [];
        result = new SecretValidationResult(state, reason, identity, scopes, reachableResources, evidence);
        return true;
    }

    private static bool TryReadHeaders(string[] lines, [NotNullWhen(true)] out Dictionary<string, string>? headers)
    {
        headers = null;
        if (lines.Length < 2 || !lines[0].Equals(SchemaLine, StringComparison.Ordinal))
        {
            return false;
        }

        var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < lines.Length; i++)
        {
            if (lines[i].Length == 0)
            {
                continue;
            }

            string[] fields = lines[i].Split('\t');
            if (fields.Length != 2)
            {
                return false;
            }

            parsed[fields[0]] = fields[1];
        }

        headers = parsed;
        return true;
    }

    private static bool TryReadExpiration(Dictionary<string, string> headers, DateTimeOffset now)
    {
        return headers.TryGetValue(ExpiresUnixTimeSecondsHeader, out string? expiresValue)
            && long.TryParse(expiresValue, CultureInfo.InvariantCulture, out long expiresUnixTimeSeconds)
            && DateTimeOffset.FromUnixTimeSeconds(expiresUnixTimeSeconds) > now;
    }

    private bool ShouldPruneEntry(string entryPath, DateTimeOffset now)
    {
        if (!TryReadAuthenticatedEntryLines(entryPath, out string[]? lines)
            || !TryReadHeaders(lines, out Dictionary<string, string>? headers)
            || !headers.TryGetValue(ExpiresUnixTimeSecondsHeader, out string? expiresValue)
            || !long.TryParse(expiresValue, CultureInfo.InvariantCulture, out long expiresUnixTimeSeconds))
        {
            return true;
        }

        return DateTimeOffset.FromUnixTimeSeconds(expiresUnixTimeSeconds) <= now;
    }

    private string CreateEntryPath(SecretValidationCacheKey key)
    {
        string shard = key.Fingerprint[..2];
        return Path.Combine(_entriesPath, shard, string.Concat(key.Fingerprint, "-", CacheFingerprintSha256, ".cache"));
    }

    private IEnumerable<string> EnumerateEntryFiles()
    {
        return Directory.Exists(_entriesPath)
            ? Directory.EnumerateFiles(_entriesPath, "*.cache", SearchOption.AllDirectories)
            : [];
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

    private static FileStream OpenOwnerOnlyNewFile(string path)
    {
        return OwnerOnlyFileSystem.OpenNewFile(path);
    }

    private static FileStream OpenOwnerOnlyFile(string path, FileMode mode, FileAccess access)
    {
        return OwnerOnlyFileSystem.OpenFile(path, mode, access);
    }

    private static void WriteOwnerOnlyText(string path, string text)
    {
        using FileStream stream = OpenOwnerOnlyNewFile(path);
        using var writer = new StreamWriter(stream, s_utf8NoBom);
        writer.Write(text);
    }

    private static void CreateOwnerOnlyDirectory(string path)
    {
        OwnerOnlyFileSystem.CreateDirectory(path);
    }

    private static void SetOwnerOnlyFile(string path)
    {
        OwnerOnlyFileSystem.ProtectFile(path);
    }
}
